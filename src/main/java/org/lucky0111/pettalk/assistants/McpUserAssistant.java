package org.lucky0111.pettalk.assistants;

import dev.langchain4j.service.SystemMessage;
import dev.langchain4j.service.UserMessage;

public interface McpUserAssistant {
    @SystemMessage("""
            당신은 AI 도우미입니다.
            """)
    String chat(@UserMessage String prompt);
}