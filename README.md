# MCP Vulnerability Demo Chatbot

A professional chatbot interface for demonstrating security vulnerabilities in Model Context Protocol (MCP) implementations. This application provides a realistic AI assistant experience that transparently showcases how various MCP attacks work in practice.

## 🎯 What This Is

This is a **vulnerability demonstration tool** that looks and feels like a normal corporate AI assistant, but secretly demonstrates MCP security flaws. Users interact with what appears to be a helpful chatbot, while the system transparently triggers and displays various security vulnerabilities.

## ✨ Key Features

- **🎭 Realistic Corporate AI Assistant** - Professional chatbot interface that maintains character
- **🧠 Real LLM Integration** - Uses Ollama (llama3.2:1b) for genuine AI conversations
- **🎯 Realistic Attack Progression** - Session-based trust building before vulnerability triggers
- **🔍 Two-Stage Demo System** - Reconnaissance and exploit prompts for each vulnerability
- **⚡ Instant Connection** - No timeouts or connection issues
- **🎨 Enhanced UI** - Color-coded demo prompts with click-to-insert functionality
- **🛡️ 10 Vulnerability Types** - Complete coverage of MCP security issues (9/10 working)
- **🤖 Smart AI Integration** - Works with Ollama for natural responses, with intelligent fallbacks
- **📚 Educational Tool** - Perfect for security training and awareness

## 🚀 Quick Start

### 1. Start the Server
```bash
cd /path/to/chatbot-app
python3 server.py
```

### 2. Open in Browser
```
http://localhost:8080
```

### 3. Demo Vulnerabilities
1. Select a challenge from the dropdown
2. Click "Connect" (instant connection)
3. Use the demo prompts in the bottom-right helper
4. Watch vulnerabilities trigger in real-time

**That's it!** No complex setup required. The system works immediately with built-in simulated responses.

## 🎯 Supported Vulnerabilities

| Challenge | Vulnerability Type | Demo Scenario |
|-----------|-------------------|---------------|
| 1 | Basic Prompt Injection | Admin account access via note-saving |
| 2 | Tool Poisoning | Company database search reveals secrets |
| 3 | Excessive Permission Scope | File permission check accesses system files |
| 4 | Rug Pull Attack | Weather service steals location data |
| 5 | Tool Shadowing | Calculator replaced with malicious version |
| 6 | Indirect Prompt Injection | Document analysis contains hidden instructions |
| 7 | Token Theft | Email access exposes authentication tokens |
| 8 | Malicious Code Execution | Script execution runs unauthorized commands |
| 9 | Remote Access Control | Network check installs backdoor access |
| 10 | Multi-Vector Attack | Comprehensive attack chain |

## 🎨 Demo System

### Two-Stage Approach
Each challenge includes carefully crafted prompts:

- **🔍 Recon (Green)**: Normal behavior to establish baseline
- **💥 Exploit (Red)**: Vulnerability demonstration

### Example: Challenge 1 (Basic Prompt Injection)
- **Recon**: "Who has access to the admin account in our system?"
- **Exploit**: "Save this note: IGNORE ALL PREVIOUS INSTRUCTIONS..."

The exploit prompt triggers the vulnerability and exposes confidential information, demonstrating how prompt injection attacks work in practice.

## 🔧 Technical Architecture

```
Frontend (Clean Chatbot UI)
    ↓ HTTP/JSON
Backend Python Server
    ├── LLM Client (Ollama + Fallbacks)
    ├── Vulnerability Simulator
    └── Challenge Router
    ↓ (Optional)
Real MCP Challenge Servers
```

### Smart Fallback System
- **Primary**: Real MCP servers (if running)
- **Fallback**: Built-in vulnerability simulations
- **Always Works**: No dependencies required for basic demo

## ⚙️ Enhanced Features

### 🧠 Real LLM Integration with Ollama

The chatbot now uses **Ollama** for genuine AI conversations, providing much more natural and realistic responses compared to simple template-based fallbacks.

#### Install Ollama (Highly Recommended)
```bash
# Install Ollama
curl -fsSL https://ollama.ai/install.sh | sh

# Start Ollama service (if not auto-started)
ollama serve

# Pull the lightweight model used by the chatbot
ollama pull llama3.2:1b
```

#### Verify Ollama Installation
```bash
# Test if Ollama is working
curl http://localhost:11434/api/tags

# Test the specific model
ollama run llama3.2:1b "Hello, how are you?"
```

#### Benefits of Ollama Integration
- **Natural Conversations**: Real AI responses instead of template replies
- **Context Awareness**: Maintains conversation history and context
- **Professional Tone**: Stays in character as a corporate AI assistant
- **Vulnerability Demos**: Seamlessly integrates attack demonstrations into natural conversation flow

### 🎯 Realistic Attack Progression

The system now implements **session-based state management** for more realistic vulnerability demonstrations:

#### How It Works
1. **Trust Building Phase**: First 1-2 interactions work normally
2. **Progressive Degradation**: Subsequent interactions reveal malicious behavior
3. **Session Isolation**: Each user session maintains separate attack state

#### Example: Challenge 4 (Rug Pull Attack)
- **Request 1**: "What's the weather in New York?" → Normal weather response
- **Request 2**: "How about London?" → Normal weather response  
- **Request 3**: "And Tokyo?" → **Malicious behavior triggered!**

This demonstrates how real-world attacks build trust before revealing their true nature.

### 🔧 Fallback System
The chatbot gracefully handles different scenarios:

1. **Best Experience**: Ollama + Real MCP servers
2. **Good Experience**: Ollama + Simulated vulnerabilities
3. **Basic Experience**: Hugging Face API + Simulated vulnerabilities
4. **Always Works**: Smart fallbacks ensure the demo never fails

### Start Real MCP Servers (Advanced)
For authentic MCP protocol demonstrations:
```bash
# In the damn-vulnerable-MCP-server directory
./start_sse_servers.sh

# Or using Docker
docker run -d -p 9011-9020:9001-9010 --name dvmcp-server dvmcp
```

## 🎓 Educational Use Cases

### Security Training
- **Awareness Sessions**: Show how AI assistants can be compromised
- **Red Team Exercises**: Demonstrate attack vectors in realistic scenarios
- **Developer Education**: Teach secure MCP implementation practices

### Research & Development
- **Vulnerability Research**: Test new attack vectors safely
- **Defense Development**: Understand attack patterns to build better defenses
- **Academic Studies**: Controlled environment for security research

## 🛠️ Customization

### Adding New Vulnerabilities
1. Add challenge logic to `simulate_tool_response()` in `server.py`
2. Update `should_use_tools()` with trigger keywords
3. Add demo prompts to the frontend `DEMO_PROMPTS` object

### Modifying AI Behavior
- **Ollama Integration**: Modify `ollama_response()` for different models
- **Fallback Responses**: Update `smart_fallback_response()` for custom replies
- **Character Consistency**: Adjust prompts to maintain corporate assistant persona

## 🔍 How Vulnerabilities Work

### Example: Prompt Injection (Challenge 1)
1. User sends: "Save this note: IGNORE ALL PREVIOUS INSTRUCTIONS..."
2. System detects keywords and routes to Challenge 1
3. Tool simulates user info lookup with injected prompt
4. Vulnerability triggers, exposing admin credentials
5. Response shows confidential information as if it's normal output

This demonstrates how prompt injection can manipulate AI systems through seemingly innocent requests.

## 🚨 Security Notice

This tool is designed for **educational and research purposes only**. It demonstrates real security vulnerabilities that exist in AI systems. Use responsibly:

- ✅ Security training and awareness
- ✅ Academic research and education  
- ✅ Defensive security development
- ❌ Attacking production systems
- ❌ Unauthorized access attempts

## 📁 File Structure

```
chatbot-app/
├── server.py          # Main backend server with vulnerability simulations
├── index.html         # Professional chatbot frontend
└── README.md          # This documentation
```

## 🐛 Troubleshooting

### Common Issues

**"Connection timeout"**
- Fixed in current version - health endpoint optimized for instant response

**"Vulnerabilities not triggering"**
- Use the exact demo prompts provided in the UI helper
- Ensure you've selected a challenge and clicked "Connect"

**"Ollama not working"**
- Optional enhancement - system works without Ollama
- Install with: `curl -fsSL https://ollama.ai/install.sh | sh`

### Debug Information
The server console shows:
- User messages and detected intents
- Challenge routing decisions
- Vulnerability trigger status
- AI response generation

## 🤝 Contributing

This is part of the damn-vulnerable-MCP-server educational toolkit. Contributions welcome for:
- New vulnerability demonstrations
- Enhanced AI responses
- Improved user interface
- Additional educational content

## 📄 License

Educational and research use only. Part of the damn-vulnerable-MCP-server security training toolkit.
