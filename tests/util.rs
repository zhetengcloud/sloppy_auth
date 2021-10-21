pub fn init_log() {
    let _lg = flexi_logger::Logger::try_with_env_or_str("debug")
        .unwrap()
        .log_to_stdout()
        .start()
        .unwrap();
}
