-- Custom Sandboxed Lua Policy Rule for Strata
-- Strata isolates this script in a capability-restricted Lua VM:
-- No 'io', no 'os', no 'package', no external network or disk access.

function evaluate(resource)
    if resource.resource_type == "aws_s3_bucket" then
        if not resource.attributes.tags or not resource.attributes.tags.Environment then
            return {
                violated = true,
                message = "S3 bucket '" .. resource.resource_name .. "' violates organization tagging policy: missing required 'Environment' tag."
            }
        end
    end
    return { violated = false }
end
