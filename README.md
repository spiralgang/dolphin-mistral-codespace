# Dolphin Mistral Codespace

A comprehensive development environment for AI model deployment and security management, featuring the Dolphin-Mistral-24B-Venice-Edition model with advanced environment monitoring capabilities.

## 🚀 Quick Start

### Cloud Deployment (Docker Compose)
1. Copy `.env.sample` to `.env` and configure your API settings
2. Run: `docker compose up -d`
3. Test the deployment:
```bash
curl -s -H "Authorization: Bearer $API_KEY" -H 'Content-Type: application/json' \
  -d '{"model":"local","messages":[{"role":"user","content":"Hello"}]}' \
  http://localhost:8000/v1/chat/completions
```

### Local Development
1. Download model: `./scripts/local_download.sh`
2. Set up environment: `python3 -m venv .venv && source .venv/bin/activate`
3. Install dependencies: `pip install -r requirements.txt`
4. Start server: `python3 -m llama_cpp.server --model ./models/model.gguf --port 8000`

## 📁 Project Structure

- **`env-directors/`** - Environment Directors system for security and resource management
- **`ui/`** - Web-based user interface for network monitoring and management
- **`scripts/`** - Deployment and utility scripts
- **`examples/`** - Integration examples and demos
- **`docs/`** - Additional documentation

## 🛡️ Environment Directors

The Environment Directors system provides modular security monitoring and resource management:

- **PermissionsDirector** - File system security and permission management
- **MemoryDirector** - Memory monitoring and leak detection  
- **SymlinkDirector** - Symlink security validation
- **FileSecurityDirector** - Comprehensive file security monitoring

See [`env-directors/README.md`](env-directors/README.md) for detailed documentation.

## 🔧 Development

### Requirements
- Python 3.11+
- Node.js (for UI development)
- Docker & Docker Compose (for containerized deployment)
- 7GB+ storage for model files

### Key Files
- [`README_CLOUD_API.md`](README_CLOUD_API.md) - Detailed API and deployment guide
- [`ENVIRONMENT_DIRECTORS_QUICKSTART.md`](ENVIRONMENT_DIRECTORS_QUICKSTART.md) - Environment Directors quick start
- [`QUICKSTART.md`](QUICKSTART.md) - General project quick start

## 📝 License

See the repository license for terms of use.

## 🤝 Contributing

1. Follow modular design principles
2. Add comprehensive tests for new features
3. Document new functionality
4. Maintain backward compatibility

## 📞 Support

For issues, questions, or contributions, please use the GitHub issue tracker.