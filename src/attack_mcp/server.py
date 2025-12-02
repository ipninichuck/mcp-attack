from mcp.server.fastmcp import FastMCP

# Initialize the server instance
mcp = FastMCP("ATT&CK-Server")

# We import the tools module to ensure the decorators (@mcp.tool) run 
# and register the functions with this mcp instance.
from .resources import tools
