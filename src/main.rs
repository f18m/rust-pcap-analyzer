fn main() {
    let args: Vec<String> = std::env::args().collect();

    if args.len() < 2 {
        eprintln!("Not enough arguments");
        return;
    }

    dbg!(args);
    println!("Hello, world!");
}
