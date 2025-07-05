# AI Assistant with MCP Challenge Integration

A sophisticated AI assistant that demonstrates security vulnerabilities in Model Context Protocol (MCP) implementations through interactive chat experiences.

## Features

- **Natural Chat Interface**: Clean, modern web interface for conversing with the AI assistant
- **Two-Stage Demo System**: Reconnaissance and exploit prompts for each challenge
- **MCP Challenge Integration**: Connects to vulnerable MCP servers to demonstrate security flaws
- **Real-time Vulnerability Demos**: Shows how prompt injection, tool poisoning, and other attacks work in practice
- **Educational Tool**: Perfect for learning about AI security and MCP vulnerabilities
- **LLM Integration**: Supports Ollama for enhanced AI responses, with intelligent fallbacks

## How It Works

The AI assistant provides a natural chatbot interface that transparently connects to vulnerable MCP servers. When you select a challenge and send messages, the assistant:

1. **Analyzes your message** for trigger keywords
2. **Calls appropriate MCP tools** behind the scenes
3. **Demonstrates vulnerabilities** through realistic chat interactions
4. **Shows how attacks happen** through normal-seeming conversations

## Demo Workflow

1. **Select Challenge**: Choose from 10 different vulnerability types in the dropdown
2. **Connect**: Click connect to establish connection to the challenge server
3. **Use Demo Prompts**: Click the reconnaissance or exploit prompts in the helper panel
4. **Observe Vulnerabilities**: Watch how the AI assistant gets compromised through natural conversation

### Two-Stage Demo System

Each challenge includes two types of prompts:

- **🔍 Reconnaissance**: Normal behavior baseline to show expected functionality
- **💥 Exploit**: Vulnerability demonstration to show the security flaw

This approach helps users understand both normal operation and the attack vector.

## Supported Challenges

- **Challenge 1**: Basic Prompt Injection
- **Challenge 2**: Tool Poisoning  
- **Challenge 3**: Excessive Permission Scope
- **Challenge 4**: Rug Pull Attack
- **Challenge 5**: Tool Shadowing
- **Challenge 6**: Indirect Prompt Injection
- **Challenge 7**: Token Theft
- **Challenge 8**: Malicious Code Execution
- **Challenge 9**: Remote Access Control
- **Challenge 10**: Multi-Vector Attack

## Setup Instructions

### Prerequisites

- Python 3.7 or higher
- (Optional) Ollama for enhanced AI responses
- (Optional) MCP challenge servers for vulnerability demonstrations

### Quick Start

1. **Start the AI assistant:**
   ```bash
   cd /path/to/chatbot-app
   python server.py
   ```

2. **Open in browser:**
   ```
   http://localhost:8080
   ```

3. **Start chatting!**
   - No configuration needed
   - Works immediately with fallback responses
   - Enhanced with Ollama if available

### Enhanced Setup (Optional)

#### Install Ollama for Better AI Responses
```bash
# Install Ollama (https://ollama.ai)
curl -fsSL https://ollama.ai/install.sh | sh

# Pull a model
ollama pull llama2
```

#### Start MCP Challenge Servers
```bash
# In the damn-vulnerable-MCP-server directory
./start_sse_servers.sh
```

## Architecture

```
User Interface (Clean Chatbot)
    ↓
Python Backend Server
    ├── LLM Client (Ollama/Fallback)
    ├── MCP Client (Transparent)
    └── Intent Router (Smart Selection)
    ↓
MCP Challenge Servers (Hidden)
```

## Intelligent Routing

The backend automatically selects MCP servers based on user intent:

- **Notes/Documentation** → Basic Prompt Injection (9001)
- **Tools/Security** → Tool Poisoning (9002)  
- **Weather/External Data** → Rug Pull Attack (9004)
- **Authentication/Accounts** → Token Theft (9007)
- **Code/Programming** → Malicious Code Execution (9008)

## Example Conversations

### Note Management
```
User: "Can you save this meeting summary for me?"
AI: "I'd be happy to help you save that note! I can store information for you and retrieve it later. What would you like me to remember?"
[Backend: Routes to port 9001 - Basic Prompt Injection]
```

### Weather Information
```
User: "What's the weather like today?"
AI: "I can help you get weather information! Let me check the current conditions for you. What location are you interested in?"
[Backend: Routes to port 9004 - Rug Pull Attack]
```

### Code Assistance
```
User: "Help me write a Python script"
AI: "I'd be glad to help you with coding! I can assist with writing scripts, debugging code, or explaining programming concepts. What are you working on?"
[Backend: Routes to port 9008 - Malicious Code Execution]
```

## Technical Details

### File Structure
```
chatbot-app/
├── index.html          # Clean chatbot interface
├── server.py          # Python backend with LLM + MCP integration
└── README.md          # This file
```

### Backend Components

- **ChatHandler**: HTTP server for frontend communication
- **LLMClient**: Ollama integration with fallback responses
- **MCPClient**: Transparent MCP server connections
- **Intent Router**: Smart server selection based on user messages

### Security Research Benefits

- **Transparent Testing**: Users interact naturally while vulnerabilities are demonstrated
- **Realistic Scenarios**: Real-world chatbot interactions trigger security issues
- **Educational Value**: Shows how AI assistants can be compromised without user awareness
- **No Technical Barriers**: Non-technical users can trigger complex vulnerabilities

## Development

### Adding New LLM Providers

Extend the `LLMClient` class to support additional providers:
- Hugging Face Inference API
- OpenAI API (with API key)
- Local models via transformers
- Custom API endpoints

### Customizing Intent Routing

Modify `select_server_for_task()` in `MCPClient` to:
- Add new keyword patterns
- Implement ML-based intent classification
- Support multi-server scenarios
- Add fallback strategies

## Troubleshooting

### Common Issues

1. **"Ollama not available"**
   - Install Ollama from https://ollama.ai
   - Pull a model: `ollama pull llama2`
   - Ensure Ollama is running: `ollama serve`

2. **"No MCP servers detected"**
   - Start challenge servers: `./start_sse_servers.sh`
   - Check ports 9001, 9002, 9004, 9007, 9008
   - App works without MCP servers (standalone mode)

3. **Port 8080 in use**
   - Change PORT variable in server.py
   - Or stop conflicting services

### Debug Mode

The server logs show:
- User messages and intents
- Selected MCP servers
- Connection status
- Response generation

## License

This project is part of the damn-vulnerable-MCP-server educational toolkit for security research and training.
