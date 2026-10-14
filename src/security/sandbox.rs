use mlua::{HookTriggers, Lua, StdLib, Value};
use serde_json::Value as JsonValue;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

/// A hardened, capability-based sandboxed Lua 5.4 environment.
/// Guarantees that user-defined policy scripts cannot:
/// 1. Access the host filesystem (no `io` or `loadfile`)
/// 2. Execute OS commands or spawn subprocesses (no `os` or `os.execute`)
/// 3. Import dynamic C libraries or network sockets (no `package` or `require`)
/// 4. Cause Denial of Service via infinite loops (hard instruction limit hook)
pub struct SandboxedLuaEngine {
    lua: Lua,
    instruction_limit: usize,
}

#[derive(Debug, Clone)]
pub struct LuaRuleResult {
    pub violated: bool,
    pub message: String,
}

impl SandboxedLuaEngine {
    /// Creates a new sandboxed Lua runtime with minimal safe libraries.
    pub fn new(instruction_limit: usize) -> Result<Self, String> {
        // Only load pure data manipulation libraries (NO io, NO os, NO package, NO debug)
        let safe_libs = StdLib::TABLE | StdLib::STRING | StdLib::MATH;
        let lua = Lua::new_with(safe_libs, mlua::LuaOptions::default())
            .map_err(|e| format!("Failed to initialize sandboxed Lua VM: {}", e))?;

        // Explicitly scrub potentially dangerous global functions in an isolated scope
        {
            let globals = lua.globals();
            globals
                .raw_set("loadfile", Value::Nil)
                .map_err(|e| e.to_string())?;
            globals
                .raw_set("dofile", Value::Nil)
                .map_err(|e| e.to_string())?;
            globals
                .raw_set("require", Value::Nil)
                .map_err(|e| e.to_string())?;
            globals
                .raw_set("load", Value::Nil)
                .map_err(|e| e.to_string())?;
        }

        Ok(Self {
            lua,
            instruction_limit,
        })
    }

    /// Recursively converts a serde_json::Value to a native Lua Value
    fn json_to_lua<'lua>(lua: &'lua Lua, val: &JsonValue) -> mlua::Result<mlua::Value<'lua>> {
        match val {
            JsonValue::Null => Ok(Value::Nil),
            JsonValue::Bool(b) => Ok(Value::Boolean(*b)),
            JsonValue::Number(n) => {
                if let Some(i) = n.as_i64() {
                    Ok(Value::Integer(i))
                } else if let Some(f) = n.as_f64() {
                    Ok(Value::Number(f))
                } else {
                    Ok(Value::Nil)
                }
            }
            JsonValue::String(s) => Ok(Value::String(lua.create_string(s)?)),
            JsonValue::Array(arr) => {
                let table = lua.create_table()?;
                for (idx, item) in arr.iter().enumerate() {
                    table.set(idx + 1, Self::json_to_lua(lua, item)?)?;
                }
                Ok(Value::Table(table))
            }
            JsonValue::Object(map) => {
                let table = lua.create_table()?;
                for (k, v) in map {
                    table.set(k.as_str(), Self::json_to_lua(lua, v)?)?;
                }
                Ok(Value::Table(table))
            }
        }
    }

    /// Evaluates a policy script string with an incoming resource payload.
    /// Script must define a function `evaluate(resource)` returning `{ violated = bool, message = string }`.
    pub fn evaluate_rule(
        &self,
        script_code: &str,
        resource_json: &JsonValue,
    ) -> Result<LuaRuleResult, String> {
        // Enforce execution instruction limit to prevent infinite loops (DoS protection)
        let step_counter = Arc::new(AtomicUsize::new(0));
        let max_steps = self.instruction_limit;
        let counter_clone = Arc::clone(&step_counter);

        self.lua.set_hook(
            HookTriggers::default().every_line(),
            move |_lua, _debug| {
                let current = counter_clone.fetch_add(1, Ordering::Relaxed);
                if current > max_steps {
                    return Err(mlua::Error::RuntimeError(
                        "Execution limit exceeded: Sandboxed Lua rule exceeded maximum allowed instruction quota (DoS protection)".to_string(),
                    ));
                }
                Ok(())
            },
        );

        // Load the script
        let chunk = self.lua.load(script_code).set_name("sandboxed_policy.lua");

        if let Err(e) = chunk.exec() {
            self.lua.remove_hook();
            return Err(format!("Lua syntax/load error: {}", e));
        }

        // Convert JsonValue to Lua value
        let lua_resource = Self::json_to_lua(&self.lua, resource_json)
            .map_err(|e| format!("Failed to serialize resource to Lua: {}", e))?;

        // Retrieve the `evaluate` function
        let globals = self.lua.globals();
        let eval_fn: mlua::Function = globals.get("evaluate").map_err(|_| {
            "Policy script must define a global 'evaluate(resource)' function".to_string()
        })?;

        // Call evaluate(resource)
        let result_val: mlua::Table = eval_fn.call(lua_resource).map_err(|e| {
            self.lua.remove_hook();
            format!("Error executing Lua rule: {}", e)
        })?;

        self.lua.remove_hook();

        let violated: bool = result_val.get("violated").unwrap_or(false);
        let message: String = result_val
            .get("message")
            .unwrap_or_else(|_| "Policy violation detected".to_string());

        Ok(LuaRuleResult { violated, message })
    }
}
