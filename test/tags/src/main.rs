/*
* Author: Marek Maślanka
* Project: DEKU
* URL: https://github.com/MarekMaslanka/deku
*/

use std::env;
use std::fs;
use std::io;
use std::path::Path;
use std::process::exit;
use regex::Regex;
use regex::RegexBuilder;

struct Function {
    name: String,
    pos: usize,
    open_bracket_pos: usize,
    end_bracket_pos: usize,
	pre_attr: String,
	is_init_exit: bool,
}

fn mod_function(fun: &Function, text: &String, buffer: &mut Vec<u8>) {
	let slice = text.as_bytes().iter().cloned();
    buffer.splice(fun.end_bracket_pos..fun.end_bracket_pos, "}".bytes());
	buffer.splice(fun.open_bracket_pos..fun.open_bracket_pos, "{".bytes());
	buffer.splice(fun.open_bracket_pos..fun.open_bracket_pos, slice);
}

fn add_before_function(fun: &Function, text: &String, buffer: &mut Vec<u8>) {
	let slice = text.as_bytes().iter().cloned();
	buffer.splice(fun.pos..fun.pos, "\n".bytes());
	buffer.splice(fun.pos..fun.pos, slice);
}

fn find_regex_from_position(buffer: &[u8], start_pos: usize, regex: &Regex) -> Option<(usize, usize)> {
    let text = String::from_utf8_lossy(&buffer[start_pos..]);
    if let Some(caps) = regex.captures(&text) {
        if let Some(m) = caps.get(0) {
            let match_start = start_pos + m.start();
            let match_end = start_pos + m.end();
            return Some((match_start, match_end));
        }
    }
    None
}

fn main() -> io::Result<()> {
	let mut file_path = "";
	let args: Vec<String> = env::args().collect();
	let mut modify_first_mid_last = false;
	let mut modify_all_functions = false;
	let mut modify_fun_at_index: Option<usize> = None;
	let mut modify_fun_with_name: Option<String> = None;
	let mut add_before_fun_with_name: Option<String> = None;
    let mut show_functions_list = false;
	let mut exclude: Vec<String> = Vec::new();
    let mut text_to_insert = "".to_string();

	if args.len() == 2 {
        file_path = args[1].as_str();
        show_functions_list = true;
    }
	else if args.len() > 4 {
		if args[1] == "mod_funcs" {
			if args[2] == "-1" {
				modify_first_mid_last = true;
				file_path = args[3].as_str();
                text_to_insert = args[4].as_str().to_owned();
			} else if args[2] == "-2" {
				modify_all_functions = true;
				file_path = args[3].as_str();
                text_to_insert = args[4].as_str().to_owned();
                if args.len() > 6 && args[5] == "--exclude"  {
                    for i in 6..args.len() {
                        exclude.push(args[i].to_string());
                    }
                }
			} else if args[2].bytes().all(|c| c.is_ascii_digit()) {
                modify_fun_at_index = Some(args[2].parse::<usize>().unwrap());
				file_path = args[3].as_str();
                text_to_insert = args[4].as_str().to_owned();
            } else {
                modify_fun_with_name = Some(args[2].to_string());
				file_path = args[3].as_str();
                text_to_insert = args[4].as_str().to_owned();
            }
		} else if args[1] == "add_before_function" {
            add_before_fun_with_name = Some(args[2].to_string());
            file_path = args[3].as_str();
            text_to_insert = args[4].as_str().to_owned();
        }
	} else {
        println!("No valid parameters");
        exit(1);
    }

    if !Path::new(file_path).exists() {
        println!("File {} doesn't exists.", file_path);
        exit(1);
    }

    text_to_insert = text_to_insert.replace("\\n", "\n");
    let mut buffer = fs::read(file_path).unwrap();
    let mut content: Vec<char> = Vec::new();

    let mut prev_char = '\0';
    let mut i = 0;
    while i < buffer.len() - 1 {
        let c = buffer[i] as char;
        if c == '/' && buffer[i + 1] as char == '/' {
            // single line comment
            while i < buffer.len() && buffer[i] as char != '\n' {
                content.push(' ');
                i += 1
            }
            prev_char = '\n';
            content.push('\n');
            i += 1;
            continue;
        }
        if c == '/' && buffer[i + 1] as char == '*' {
            // multi line comment
            content.push(' ');
            i += 1;
            while i < buffer.len() - 1
                && !(buffer[i - 1] as char == '*' && buffer[i] as char == '/')
            {
                if buffer[i] as char == '\n' {
                    content.push('\n');
                } else {
                	content.push(' ');
				}
                i += 1;
            }
            prev_char = buffer[i] as char;
            content.push(' ');
            i += 1;
            continue;
        }
        if c == '#' && prev_char == '\n' {
            // check if it's "#ifdef CONFIG_XXX"
            let result = find_regex_from_position(&buffer, i, &Regex::new(r"#ifdef").unwrap());
            let ifdef_config_suspend = find_regex_from_position(&buffer, i, &Regex::new(r"#ifdef CONFIG_SUSPEND").unwrap());
            if !result.is_none() && result.unwrap().0 == i && !(!ifdef_config_suspend.is_none() && result.unwrap().0 == ifdef_config_suspend.unwrap().0) {
                let endif_result = find_regex_from_position(&buffer, result.unwrap().1, &Regex::new(r"#endif").unwrap());
                if !endif_result.is_none() {
                    let j = endif_result.unwrap().1;
                    while i < j
                    {
                        if buffer[i] as char == '\n' {
                            content.push('\n');
                        } else {
                            content.push(' ');
                        }
                        prev_char = buffer[i] as char;
                        i += 1;
                    }
                    continue;
                } else {
                    println!("Can't find #endif");
                    exit(1);
                }
            }

            // pre-processor
            while i < buffer.len() - 1
                && !(buffer[i - 1] as char != '\\' && buffer[i] as char == '\n')
            {
                if buffer[i] as char == '\n' {
                    content.push('\n');
                } else {
                	content.push(' ');
				}
                i += 1;
            }
            prev_char = buffer[i] as char;
            content.push('\n');
            i += 1;
            continue;
        }
        if c == '{' {
            content.push('{');
            i += 1;
            let mut cnt = 1;
            while i < buffer.len() - 1 {
                if buffer[i] as char == '\n' {
                    content.push('\n');
                    i += 1;
                    continue;
                }
                if buffer[i] as char == '{' {
                    cnt += 1;
                } else if buffer[i] as char == '}' {
                    cnt -= 1;
                    if cnt == 0 || /* force end function if the close bracket is at very beginning of the line */ buffer[i - 1] as char == '\n'{
                        break;
                    }
                }
                content.push(' ');
                i += 1;
            }
            prev_char = buffer[i] as char;
            content.push('}');
            i += 1;
            continue;
        }

        content.push(c);
        prev_char = buffer[i] as char;
        i += 1;
    }

    let text = String::from_iter(content.iter());
	let mut init_function = "".to_string();
	let mut re = Regex::new(r"module_init\((\w+)\)").unwrap();
	for cap in re.captures_iter(text.as_str()) {
		init_function = cap[1].to_string();
	}
	let mut exit_function = "".to_string();
	re = Regex::new(r"module_exit\((\w+)\)").unwrap();
	for cap in re.captures_iter(text.as_str()) {
		exit_function = cap[1].to_string();
	}

    re = RegexBuilder::new(r"^([\w\s]+)\s+[\s\\*]*(\w+)\([\w\s,\\*]*\)\s*(\w+)?\s*\{(\s+)(\})")
        .multi_line(true)
        .build()
        .unwrap();

	let mut functions: Vec<Function> = Vec::new();
    for caps in re.captures_iter(text.as_str()) {
        let mut fun: Function = Function {
            name: String::from(&caps[2]),
            pos: caps.get(1).unwrap().start(),
            open_bracket_pos: caps.get(4).unwrap().start(),
            end_bracket_pos: caps.get(5).unwrap().start(),
			pre_attr: caps[1].trim().to_string(),
			is_init_exit: false,
        };
		if fun.name == init_function.as_str() || fun.pre_attr == "__init" {
			fun.is_init_exit = true;
		}
		if fun.name == exit_function.as_str() || fun.pre_attr == "__exit" {
			fun.is_init_exit = true;
		}
		if (modify_first_mid_last || modify_all_functions) && fun.is_init_exit {
			continue
		}
        if exclude.iter().any(|ex| ex == &fun.name) {
            continue
        }
		functions.push(fun);
    }
    let mut write_the_buffer = false;
	if modify_first_mid_last || modify_all_functions {
        if functions.is_empty() {
            println!("No functions found");
            return Ok(());
        }
        if modify_all_functions {
            for i in (0..functions.len()).rev() {
                mod_function(&functions[i], &text_to_insert, &mut buffer);
            }
        } else {
            let mut fun = functions.last().unwrap();
            mod_function(fun, &text_to_insert, &mut buffer);
            fun = &functions[functions.len() / 2];
            mod_function(fun, &text_to_insert, &mut buffer);
            fun = functions.first().unwrap();
            mod_function(fun, &text_to_insert, &mut buffer);
        }
        write_the_buffer = true;
    } else if modify_fun_at_index.is_some() {
		let fun = &functions[modify_fun_at_index.unwrap()];
		mod_function(fun, &text_to_insert, &mut buffer);
        write_the_buffer = true;
	} else if modify_fun_with_name.is_some() {
        let fun_name = modify_fun_with_name.unwrap();
        match functions.into_iter().find(|fun| fun.name == fun_name) {
            Some(fun) => {
                mod_function(&fun, &text_to_insert, &mut buffer);
                write_the_buffer = true;
            },
            None => {
                println!("Can't find function: {}", fun_name);
                exit(1);
            }
        };
    } else if add_before_fun_with_name.is_some() {
        let fun_name = add_before_fun_with_name.unwrap();
        match functions.into_iter().rev().find(|fun| fun.name == fun_name) {
            Some(fun) => {
                add_before_function(&fun, &text_to_insert, &mut buffer);
                write_the_buffer = true;
            },
            None => {
                println!("Can't find function: {}", fun_name);
                exit(1);
            }
        };
    } else if show_functions_list {
        for fun in functions {
            println!("{} {}:{}", fun.pre_attr, fun.name, fun.pos);
        }
    }
    if write_the_buffer {
        let res = fs::write(file_path, buffer);
        if res.is_err() {
            println!("Can't write the output file");
            exit(1);
        }
    }

    Ok(())
}
