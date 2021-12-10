use client::{eat_err, DB};
use iced::{
    button, executor, text_input, Application, Button, Clipboard, Column,
    Command, Element, Settings, Text, TextInput, Radio
};
use std::sync::Mutex;
use std::time::Duration;
use std::sync::atomic::Ordering;

fn main() -> iced::Result {
    pretty_env_logger::init_timed();

    NymDrive::run(Settings {
        window: iced::window::Settings {
            size: (600, 600),
            min_size: Some((600, 600)),
            max_size: Some((600, 600)),
            ..Default::default()
        },
        ..Default::default()
    })
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProxyChoice {
    Disabled,
    Enabled,
}

#[derive(Default)]
struct NymDrive {
    login_button: button::State,
    logout_button: button::State,
    username: text_input::State,
    username_value: String,
    password: text_input::State,
    password_value: String,
    logged_in: bool,
    use_proxy_value: bool,
}

#[derive(Debug, Clone)]
enum Message {
    LoginPressed,
    LogoutPressed,
    UsernameChanged(String),
    PasswordChanged(String),
    Init(bool, bool, String, String),
    ProxySelected(ProxyChoice),
}

lazy_static::lazy_static! {
    static ref CLIENT_HANDLE: Mutex<Option<tokio::task::JoinHandle<()>>> = Mutex::new(None);
}

fn fire_and_forget(username: &str, password: &str, use_proxy: bool) {
    let username = username.to_string();
    let password = password.to_string();

    client::USE_PROXY.store(use_proxy, Ordering::Relaxed);

    *CLIENT_HANDLE.lock().unwrap() = Some(tokio::spawn(async move {
        let rec = sqlx::query!("SELECT COUNT(*) as count FROM meta;")
            .fetch_one(&*DB)
            .await
            .unwrap();

        if rec.count < 1 {
            eat_err!(
                sqlx::query!(
                    "INSERT INTO meta (username, password, use_proxy) VALUES (?, ?, ?);",
                    username,
                    password,
                    use_proxy
                )
                .execute(&*DB)
                .await
            );
        } else {
            dbg!(use_proxy);
            eat_err!(
                sqlx::query!(
                    "UPDATE meta SET use_proxy = ?;",
                    use_proxy
                )
                .execute(&*DB)
                .await
            );
        }

        match client::run().await {
            Ok(_) => {}
            Err(e) => {
                log::error!("{}", e);
                if e.to_string() == "unauthorized" {
                    log::error!("INCORRECT PASSWORD");

                    eat_err!(
                        sqlx::query!("DELETE FROM meta;").execute(&*DB).await
                    );

                    std::process::exit(-1);
                }
            }
        }
    }));
}

impl Application for NymDrive {
    type Executor = executor::Default;
    type Message = Message;
    type Flags = ();

    fn new(_flags: ()) -> (Self, Command<Self::Message>) {
        (
            Default::default(),
            Command::perform(
                sqlx::query!("SELECT * FROM meta;").fetch_optional(&*DB),
                |rec| {
                    let res = match rec.unwrap() {
                        Some(v) => {
                            let use_proxy = v.use_proxy != 0;
                            fire_and_forget(&v.username, &v.password, use_proxy);
                            (true, use_proxy, v.username, v.password)
                        }
                        None => (false, false, "".into(), "".into()),
                    };
                    Message::Init(res.0, res.1, res.2, res.3)
                },
            ),
        )
    }

    fn title(&self) -> String {
        String::from("NymDrive")
    }

    fn update(
        &mut self,
        message: Message,
        _: &mut Clipboard,
    ) -> Command<Self::Message> {
        match message {
            Message::LoginPressed => {
                if self.logged_in {
                    return Command::none();
                } else if self.username_value.is_empty()
                    || self.password_value.is_empty()
                {
                    return Command::none();
                }

                self.logged_in = true;
                fire_and_forget(&self.username_value, &self.password_value, self.use_proxy_value);
            }
            Message::LogoutPressed => {
                self.logged_in = false;
                self.username_value.clear();
                self.password_value.clear();

                return Command::perform(
                    sqlx::query!("DELETE FROM meta; DELETE FROM files;")
                        .execute(&*DB),
                    |r| {
                        eat_err!(r);

                        let h = CLIENT_HANDLE.lock().unwrap().take().unwrap();

                        h.abort();

                        log::info!("Gracefully exiting to ensure cleanup...");

                        std::thread::sleep(Duration::from_millis(1500));

                        let dir = home::home_dir().unwrap().join("nymdrive");
                        let _ = std::fs::remove_dir_all(dir);

                        std::process::exit(0);
                    },
                );
            }
            Message::UsernameChanged(s) => {
                self.username_value = s;
            }
            Message::PasswordChanged(s) => {
                self.password_value = s;
            }
            Message::Init(logged_in, use_proxy, username, pass) => {
                self.logged_in = logged_in;
                self.use_proxy_value = use_proxy;
                self.username_value = username;
                self.password_value = pass;
            }
            Message::ProxySelected(v) => {
                self.use_proxy_value = if v == ProxyChoice::Enabled {
                    true
                } else {
                    false
                };
            }
        }

        Command::none()
    }

    fn view(&mut self) -> Element<Message> {
        let proxy_choice = if self.use_proxy_value {
            Some(ProxyChoice::Enabled)
        } else {
            Some(ProxyChoice::Disabled)
        };

        let c = Column::new()
            .padding(20)
            .spacing(10)
            .push(Text::new("").size(20));

        let c = if self.logged_in {
            c
                .push(Text::new("Logged in as: ".to_owned() + &self.username_value).size(30))
                .push(Text::new("").size(20))
                .push(
                    Button::new(&mut self.logout_button, Text::new("Logout and locally wipe ~/nymdrive"))
                        .on_press(Message::LogoutPressed),
                )
                .push(Text::new("").size(20))
                .push(Text::new("NOTE: Logging out will only remove files locally. If you wish to remove a file on both ends, simply delete it from the ~/nymdrive directory in your filesystem. Closing this window will keep you logged in.").size(20))
                .push(Text::new("Sync directory: ~/nymdrive").size(20))
                .push(Text::new("Ciphertext file hashes are accessible in the file hash GUI by executing the command ./file_hashes.sh in the repo root. The file hashes are presented as: data_ciphertext_digest.").size(16))
        } else {
            c.push(Text::new("Username:").size(30))
                .push(
                    TextInput::new(
                        &mut self.username,
                        "",
                        &self.username_value,
                        Message::UsernameChanged,
                    )
                    .size(30),
                )
                .push(Text::new("Password:").size(30))
                .push(
                    TextInput::new(
                        &mut self.password,
                        "",
                        &self.password_value,
                        Message::PasswordChanged,
                    )
                    .size(30)
                    .password(),
                )
                .push(Text::new("").size(20))
                .push(
                    Button::new(
                        &mut self.login_button,
                        Text::new("Login/sign up"),
                    )
                    .on_press(Message::LoginPressed),
                )
                .push(Radio::new(ProxyChoice::Enabled, "Route traffic through mixnet", proxy_choice, Message::ProxySelected))
                .push(Radio::new(ProxyChoice::Disabled, "Do not route traffic through mixnet", proxy_choice, Message::ProxySelected))
                .push(Text::new("NOTE: The current testnet mixnet can be unstable and may not be functional at all times. You may disable the mixnet to purely test the syncing functionality. Your synced files will be tied to the same account whether or not you enable the mixnet.").size(16))
        };

        c.into()
    }
}
