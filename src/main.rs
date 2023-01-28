use lazy_static::{__Deref, lazy_static};
use log::error;
use read_input::prelude::*;
use simplelog::{ColorChoice, Config, LevelFilter, TermLogger, TerminalMode};
use std::collections::{HashMap, HashSet};
use std::error::Error;
use std::fs::File;
use std::io::{BufReader, BufWriter, stdin, stdout, Write};
use std::path::Path;
use std::sync::Mutex;
use sanitizer::StringSanitizer;

const DATABASE_FILE: &str = "db.txt";
const MAXIMUM_PASSWORD_LENGTH: usize = 32;
const MAXIMUM_USERNAME_LENGTH: usize = 128;
const MINIMUM_USERNAME_LENGTH: usize = 1;

lazy_static! {
    static ref GRADE_DATABASE: Mutex<HashMap<String, Vec<f32>>> = {
        let map = read_database_from_file(DATABASE_FILE).unwrap_or(HashMap::new());
        Mutex::new(map)
    };
    static ref PROF_CREDENTIALS: HashSet<(String, String)> = {
        let mut set = HashSet::new();
        set.insert(("danono".to_string(), "3lves4ndH0b1ts".to_string()));
        set.insert(("duc".to_string(), "l4crypt0C3stR1g0l0".to_string()));
        set
    };
}

fn read_database_from_file<P: AsRef<Path>>(
    path: P,
) -> Result<HashMap<String, Vec<f32>>, Box<dyn Error>> {
    let file = File::open(path)?;
    let reader = BufReader::new(file);
    let map = serde_json::from_reader(reader)?;
    Ok(map)
}

fn welcome() {
    println!("Welcome to KING: KING Is Not GAPS");
}

fn menu(teacher: &mut bool) {
    if *teacher {
        teacher_action();
    } else {
        student_action(teacher);
    }
}

fn student_action(teacher: &mut bool) {
    println!("*****\n1: See your grades\n2: Teachers' menu\n3: About\n0: Quit");
    let choice = input().inside(0..=2).msg("Enter Your choice: ").get();
    match choice {
        1 => show_grades("Enter your name. Do NOT lie!"),
        2 => become_teacher(teacher),
        0 => quit(),
        _ => panic!("impossible choice"),
    }
}

fn teacher_action() {
    println!("*****\n1: See grades of student\n2: Enter grades\n3 About\n0: Quit");
    let choice = input().inside(0..=2).msg("Enter Your choice: ").get();
    match choice {
        1 => show_grades("Enter the name of the user of which you want to see the grades:"),
        2 => enter_grade(),
        0 => quit(),
        _ => panic!("impossible choice"),
    }
}

fn show_grades(message: &str) {
    println!("{}", message);
    let name: String = input().get();
    println!("Here are the grades of user {}", name);
    let db = GRADE_DATABASE.lock().unwrap();
    match db.get(&name) {
        Some(grades) => {
            println!("{:?}", grades);
            println!(
                "The average is {}",
                (grades.iter().sum::<f32>()) / ((*grades).len() as f32)
            );
        }
        None => panic!("User not in system"),
    };
}

fn become_teacher(teacher: &mut bool) {
    match login() {
        Ok(result) => {
            if result {
                *teacher = true;
                return;
            } else {
                println!("Wrong credentials");
            }
        }
        Err(_) => {
            println!("Failed login")
        },
    }
    *teacher = false;
}

fn enter_grade() {
    println!("What is the name of the student?");
    let name: String = input()
        .add_test(|x: &String| !x.is_empty() && x.len() <= MAXIMUM_USERNAME_LENGTH).get();
    println!("What is the new grade of the student?");
    let grade: f32 = match input()
        .add_test(|x: &String| x.parse::<f32>().is_ok())
        .add_test(|x: &String| {
            let grade: f32 = x.parse().unwrap();
            grade.trunc() >= 0.0 && grade.trunc() <= 6.0 && (grade * 10.0).fract() == 0.0
            && !(grade.trunc() == 6.0 && grade.fract() != 0.0)
        })
        .try_get() {
        Ok(grade) => {
            let grade: f32 = grade.parse().unwrap();
            grade
        }
        Err(_) => panic!("Invalid grade"),
    };
    let mut map = GRADE_DATABASE.lock().unwrap();
    match map.get_mut(&name) {
        Some(v) => v.push(grade),
        None => {
            map.insert(name, vec![grade]);
        }
    };
}


fn quit() {
    println!("Saving database!");
    let file = File::create(DATABASE_FILE).unwrap();
    let writer = BufWriter::new(file);
    serde_json::to_writer(writer, GRADE_DATABASE.lock().unwrap().deref()).unwrap();
    std::process::exit(0);
}

fn login() -> std::io::Result<bool> {

    let username = match get_name("Enter your username: ") {
        Ok(username) => {
            username
        },
        Err(e) => {
            return Err(e);
        }
    };
    let password = match get_password("Enter your password: ") {
        Ok(password) => password,
        Err(e) => {
            return Err(e);
        }
    };

    if PROF_CREDENTIALS.contains(&(username.clone(), password.clone())) {
        Ok(true)
    } else {
        Ok(false)
    }
}

fn sanitize_name(name: String) -> String {
    let mut sanitize = StringSanitizer::from(name);
    sanitize.trim().alphanumeric().to_lowercase().clamp_max(MAXIMUM_USERNAME_LENGTH);
    sanitize.get()
}

fn sanitize_password(password: String) -> String {
    let mut sanitize = StringSanitizer::from(password);
    sanitize.trim().clamp_max(MAXIMUM_PASSWORD_LENGTH);
    sanitize.get()
}

fn get_name(message: &str) -> std::io::Result<String> {
    return match input()
        .msg(message)
        .add_test(|x : &String| x.len() <= MAXIMUM_USERNAME_LENGTH)
        .try_get(){
        Ok(name) => {
            Ok(sanitize_name(name))
        },
        Err(e) => {
            Err(e)
        }
    };
}

fn get_password(message: &str) -> std::io::Result<String> {
    return match input()
        .msg(message)
        .add_test(|x : &String| x.len() <= MAXIMUM_PASSWORD_LENGTH)
        .try_get(){
        Ok(password) => {
            Ok(sanitize_password(password))
        },
        Err(e) => {
            Err(e)
        }
    };
}
fn main() {
    TermLogger::init(
        LevelFilter::Trace,
        Config::default(),
        TerminalMode::Stderr,
        ColorChoice::Auto,
    )
    .unwrap();
    welcome();
    let mut teacher = false;
    loop {
        menu(&mut teacher);
    }
}
