from .server import mcp
from .core.graph import knowledge_base

def main():
    # Optional: Pre-load the graph on startup so the first request isn't slow
    print("🚀 Initializing ATT&CK MCP Server...")
    try:
        knowledge_base.build()
    except Exception as e:
        print(f"⚠️ Warning: Could not download ATT&CK data on startup: {e}")
    
    # Run the MCP server
    mcp.run()

if __name__ == "__main__":
    main()
