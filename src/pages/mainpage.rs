use crate::web_sys::CloseEvent;
use thaw::*;
use leptos::ev::Event;
use leptos::*;
use leptos_use::core::ConnectionReadyState;
use leptos_use::{use_websocket_with_options, UseWebSocketOptions};
use shv::client::LoginParams;
use shv::util::{login_from_url, sha1_password_hash};
use shv::RpcMessage;
use url::Url;

#[component]
pub fn MainPage() -> impl IntoView {
    let (is_connect, set_connect) = create_signal(false);
    let (is_socket_connected, set_socket_connected) = create_signal(false);
    //let (text, set_text) = create_signal("wss://nirvana.elektroline.cz:37778?user=iot&password=lub42DUB".to_owned());

    // let input_url: NodeRef<html::Input> = create_node_ref();
    let url_sig = create_rw_signal(String::from("wss://nirvana.elektroline.cz:37778?user=iot&password=test"));
    view! {
        //<Box style="display: flex; flex-direction: column; align-items: center; padding: 1em; min-height: 100%; min-width: 100%">
        <div>
            <h2>"Welcome to Websocketosaurus"</h2>
            <Space>
                <label for="url-str">"Url"</label>
                <Input value=url_sig attr:id="url-str"/>
            </Space>
            <Space>
                <span>"socket connected: " {move || is_socket_connected.get()}</span>
                <ButtonGroup>
                    <Button on_click=move|_| set_connect.set(true) disabled=Signal::derive(move|| is_connect.get())>"Connect"</Button>
                    <Button on_click=move|_| set_connect.set(false) disabled=Signal::derive(move|| !is_connect.get())>"Disconnect"</Button>
                </ButtonGroup>
            </Space>
            {move || if is_connect.get() {
                let url_str = url_sig.get_untracked();
                view! {
                    <Wss url=url_str socket_connected=set_socket_connected />
                }
            } else {
                "Websocket is closed".into_view()
            }}
        </div>
    }
}

#[component]
fn Wss(
    #[prop(into)] url: String,
    #[prop(into)] socket_connected: WriteSignal<bool>,
) -> impl IntoView {
    let (log, set_log) = create_signal(vec![]);
    #[derive(Clone)]
    enum LoginStatus {
        Connected,
        Hello,
        Login,
        Ok,
        Error,
    }
    let (login_status, set_login_status) = create_signal(LoginStatus::Connected);

    fn append_log(log: &WriteSignal<Vec<String>>, message: String) {
        let _ = log.update(|log: &mut Vec<_>| log.push(message));
    }

    let on_open_callback = move |e: Event| {
        set_log.update(|log: &mut Vec<_>| log.push(format! {"[onopen]: event {:?}", e.type_()}));
    };

    let on_close_callback = move |e: CloseEvent| {
        set_log.update(|log: &mut Vec<_>| log.push(format! {"[onclose]: event {:?}", e.type_()}));
    };

    let on_error_callback = move |e: Event| {
        set_log.update(|log: &mut Vec<_>| log.push(format! {"[onerror]: event {:?}", e.type_()}));
    };

    //let on_message_callback = move |m: String| {
    //    set_log.update(|log: &mut Vec<_>| {
    //        log.push(format! {"[onmessage]: {}", m})
    //    });
    //};

    //let on_message_bytes_callback = move |m: Vec<u8>| {
    //    set_log.update(|log: &mut Vec<_>| {
    //        log.push(format! {"[onmessage-data]: {:?}", m})
    //    });
    //};

    let ws = use_websocket_with_options(
        &url,
        UseWebSocketOptions::default()
            .immediate(true)
            .on_open(on_open_callback.clone())
            .on_close(on_close_callback.clone())
            .on_error(on_error_callback.clone()), //.on_message(on_message_callback.clone())
                                                  //.on_message_bytes(on_message_bytes_callback.clone()),
    );
    let url = Url::parse(&url).expect("valid url");

    let send_byte_message = move |bytes: Vec<u8>| {
        //append_log(&set_log, format! {"[send_bytes]: {:?}", &bytes});
        (ws.send_bytes)(bytes);
    };
    let send_request = move |rq: shv::RpcMessage| {
        append_log(&set_log, format! {"[request]: {}", rq.to_cpon()});
        let frame = rq.to_frame().expect("valid hello message");
        let mut buff: Vec<u8> = vec![];
        shv::streamrw::write_frame(&mut buff, frame).expect("valid hello frame");
        send_byte_message(buff);
    };

    let send_request2 = send_request.clone();
    let call_method = move |shv_path: &str, method: &str, param: &str| {
        let param = if param.is_empty() {
            None
        } else {
            match shv::RpcValue::from_cpon(param) {
                Ok(rv) => Some(rv),
                Err(_) => None,
            }
        };
        let rq = RpcMessage::new_request(shv_path, method, param);
        send_request2(rq);
    };

    let status = move || ws.ready_state.get().to_string();

    create_effect(move |_| {
        if let Some(m) = ws.message.get() {
            append_log(&set_log, format! {"[message]: {:?}", m});
        };
    });

    let connected = move || ws.ready_state.get() == ConnectionReadyState::Open;

    let send_request2 = send_request.clone();
    create_effect(move |_| {
        let sc = connected();
        socket_connected.set(sc);
        if sc {
            // send hello
            let rq = shv::RpcMessage::new_request("", "hello", None);
            send_request2(rq);
            set_login_status.set(LoginStatus::Hello);
        }
    });

    create_effect(move |_| {
        if let Some(data) = ws.message_bytes.get() {
            let frame = shv::streamrw::read_frame(&data).expect("valid response frame");
            let resp = frame.to_rpcmesage().expect("valid response message");
            // append_log(&set_log, format! {"[message_bytes]: {:?}", &data});
            append_log(&set_log, format! {"[response]: {}", resp.to_cpon()});
            match login_status.get() {
                LoginStatus::Hello => {
                    let nonce = resp
                        .result()
                        .expect("valid hello response")
                        .as_map()
                        .get("nonce")
                        .expect("nonce")
                        .as_str();
                    let (user, password) = login_from_url(&url);
                    let hash = sha1_password_hash(password.as_bytes(), nonce.as_bytes());
                    let password = std::str::from_utf8(&hash).expect("ascii7 string").into();
                    let login_params = LoginParams {
                        user,
                        password,
                        reset_session: false,
                        ..Default::default()
                    };
                    let rq = RpcMessage::new_request("", "login", Some(login_params.to_rpcvalue()));
                    send_request(rq);
                    set_login_status.set(LoginStatus::Login);
                }
                LoginStatus::Login => match resp.result() {
                    Ok(_) => {
                        set_login_status.set(LoginStatus::Ok);
                        append_log(&set_log, format! {"[login OK]"});
                    }
                    Err(err) => {
                        set_login_status.set(LoginStatus::Error);
                        append_log(&set_log, format! {"[login error]: {}", err.to_string()});
                    }
                },
                LoginStatus::Ok => {}
                _ => {}
            }
        };
    });

    let input_shvpath: NodeRef<html::Input> = create_node_ref();
    let input_method: NodeRef<html::Input> = create_node_ref();
    let input_param: NodeRef<html::Input> = create_node_ref();

    view! {
        <div class="container">
            <div>
                <h2>"Websocket"</h2>
                <p>"status: " {status}</p>
                "shv path"
                <input type="text" size="50" value="" node_ref=input_shvpath/>
                "method"
                <input type="text" value="dir" node_ref=input_method/>
                "param"
                <input type="text" value="" node_ref=input_param/>

                <button
                    on:click= move |_| {
                        call_method(&input_shvpath.get().unwrap().value(), &input_method.get().unwrap().value(), &input_param.get().unwrap().value());
                    }
                    disabled=move || !connected()
                >
                    "Send"
                </button>
                //<button on:click=send_byte_message disabled=move || !connected()>
                //    "Send Bytes"
                //</button>
                <div>
                    <h3>"Log"</h3>
                    <button
                        on:click=move |_| set_log.set(vec![])
                        disabled=move || log.get().len() <= 0
                    >
                        "Clear"
                    </button>
                </div>
                <For
                    each=move || log.get().into_iter().enumerate()
                    key=|(index, _)| *index
                    let:item
                >
                    <div>{item.1}</div>
                </For>
            </div>
        </div>
    }
}
