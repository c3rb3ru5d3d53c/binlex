use rmcp::model::{GetPromptResult, Prompt, PromptArgument, PromptMessage, PromptMessageRole};

#[derive(Clone)]
pub struct SkillPrompt {
    pub prompt: Prompt,
    pub instructions: Option<String>,
    pub python: Option<String>,
}

impl SkillPrompt {
    pub fn from_config(skill: &crate::state::McpSkill) -> Self {
        Self {
            prompt: Prompt::new(
                skill.name.clone(),
                Some(skill.description.clone()),
                Some(vec![
                    PromptArgument::new("goal")
                        .with_description("Optional user goal or context for this skill.")
                        .with_required(false),
                ]),
            ),
            instructions: skill.instructions.clone(),
            python: skill.python.clone(),
        }
    }

    pub fn render(&self, goal: Option<&str>) -> GetPromptResult {
        let mut content = String::new();
        if let Some(description) = &self.prompt.description {
            content.push_str(description.trim());
            content.push_str("\n\n");
        }
        if let Some(instructions) = &self.instructions {
            content.push_str("Instructions:\n");
            content.push_str(instructions.trim());
            content.push_str("\n\n");
        }
        if let Some(python) = &self.python {
            content.push_str("Python Example:\n```python\n");
            content.push_str(python.trim());
            content.push_str("\n```\n");
        }
        if let Some(goal) = goal {
            content.push_str("\nRequested goal:\n");
            content.push_str(goal);
        }

        let mut result = GetPromptResult::new(vec![PromptMessage::new_text(
            PromptMessageRole::User,
            content,
        )]);
        if let Some(description) = self.prompt.description.clone() {
            result = result.with_description(description);
        }
        result
    }
}
