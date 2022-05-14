use log::error;
use zecwallet_cli::{
    attempt_recover_seed, configure_clapapp, report_permission_error, start_interactive, startup, version::VERSION,
};
use zecwalletlitelib::{
    lightclient::{self, lightclient_config::LightClientConfig},
    MainNetwork,
};

pub fn main() {
    // Get command line arguments
    use clap::{App, Arg};
    let fresh_app = App::new("Zecwallet CLI");
    let configured_app = configure_clapapp!(fresh_app);
    let matches = configured_app.get_matches();

    if matches.is_present("recover") {
        // Create a Light Client Config in an attempt to recover the file.
        attempt_recover_seed(matches.value_of("password").map(|s| s.to_string()));
        return;
    }

    let command = matches.value_of("COMMAND");
    let params = matches
        .values_of("PARAMS")
        .map(|v| v.collect())
        .or(Some(vec![]))
        .unwrap();

    let maybe_server = matches.value_of("server").map(|s| s.to_string());

    let maybe_data_dir = matches.value_of("data-dir").map(|s| s.to_string());

    let seed = matches.value_of("seed").map(|s| s.to_string());
    let maybe_birthday = matches.value_of("birthday");

    if seed.is_some() && maybe_birthday.is_none() {
        eprintln!("ERROR!");
        eprintln!("Please specify the wallet birthday (eg. '--birthday 600000') to restore from seed.");
        eprintln!("This should be the block height where the wallet was created. If you don't remember the block height, you can pass '--birthday 0' to scan from the start of the blockchain.");
        return;
    }

    let birthday = match maybe_birthday.unwrap_or("0").parse::<u64>() {
        Ok(b) => b,
        Err(e) => {
            eprintln!("Couldn't parse birthday. This should be a block number. Error={}", e);
            return;
        }
    };

    let server = LightClientConfig::<MainNetwork>::get_server_or_default(maybe_server);

    // Test to make sure the server has all of scheme, host and port
    if server.scheme_str().is_none() || server.host().is_none() || server.port().is_none() {
        eprintln!(
            "Please provide the --server parameter as [scheme]://[host]:[port].\nYou provided: {}",
            server
        );
        return;
    }

    let nosync = matches.is_present("nosync");

    let startup_chan = startup(server, seed, birthday, maybe_data_dir ,!nosync, command.is_none());
    let (command_tx, resp_rx) = match startup_chan {
        Ok(c) => c,
        Err(e) => {
            let emsg = format!("Error during startup:{}\nIf you repeatedly run into this issue, you might have to restore your wallet from your seed phrase.", e);
            eprintln!("{}", emsg);
            error!("{}", emsg);
            if cfg!(target_os = "unix") {
                match e.raw_os_error() {
                    Some(13) => report_permission_error(),
                    _ => {}
                }
            };
            return;
        }
    };

    if command.is_none() {
        start_interactive(command_tx, resp_rx);
    } else {
        command_tx
            .send((
                command.unwrap().to_string(),
                params.iter().map(|s| s.to_string()).collect::<Vec<String>>(),
            ))
            .unwrap();

        match resp_rx.recv() {
            Ok(s) => println!("{}", s),
            Err(e) => {
                let e = format!("Error executing command {}: {}", command.unwrap(), e);
                eprintln!("{}", e);
                error!("{}", e);
            }
        }

        // Save before exit
        command_tx.send(("save".to_string(), vec![])).unwrap();
        resp_rx.recv().unwrap();
    }
}
