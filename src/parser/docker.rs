use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DockerInstruction {
    pub instruction: String,
    pub arguments: String,
    pub line_number: usize,
    pub raw_line: String,
}

pub struct DockerParser;

impl DockerParser {
    pub fn parse_file(content: &str) -> Vec<DockerInstruction> {
        let mut instructions = Vec::new();
        let lines: Vec<&str> = content.lines().collect();

        for (idx, line) in lines.iter().enumerate() {
            let trimmed = line.trim();
            if trimmed.is_empty() || trimmed.starts_with('#') {
                continue;
            }

            if let Some((inst, args)) = trimmed.split_once(' ') {
                let upper_inst = inst.to_uppercase();
                match upper_inst.as_str() {
                    "FROM" | "RUN" | "CMD" | "LABEL" | "EXPOSE" | "ENV" | "ADD" | "COPY"
                    | "ENTRYPOINT" | "VOLUME" | "USER" | "WORKDIR" | "ARG" | "ONBUILD"
                    | "STOPSIGNAL" | "HEALTHCHECK" | "SHELL" => {
                        instructions.push(DockerInstruction {
                            instruction: upper_inst,
                            arguments: args.trim().to_string(),
                            line_number: idx + 1,
                            raw_line: trimmed.to_string(),
                        });
                    }
                    _ => {}
                }
            }
        }

        instructions
    }
}
