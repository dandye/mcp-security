# Function Calling vs. MCP Tools

This document explains the difference between OpenAI Function Calling and the Model Context Protocol (MCP), and why we provide both implementations for certain tools in this repository.

## What is Function Calling?

[Function Calling](https://platform.openai.com/docs/guides/function-calling) (also known as "Tool Calling") is a feature of OpenAI's API (and other LLM providers) that allows you to describe functions to the model. The model can then intelligently choose to output a JSON object containing arguments to call one of these functions.

In a Function Calling workflow:
1.  **You define tools**: You pass a JSON schema describing your functions (name, description, parameters) to the LLM API.
2.  **Model decides**: The model processes your prompt and decides if it needs to call a tool. If so, it returns a structured response (JSON) with the function name and arguments.
3.  **You execute**: Your code parses the model's response, calls the actual function in your codebase with the provided arguments, and gets the result.
4.  **Model responds**: You send the function's output back to the model, which then generates a natural language response incorporating the data.

## What is MCP (Model Context Protocol)?

[MCP](https://modelcontextprotocol.io/) is an open standard for exposing tools and resources to LLMs. It abstracts away the specific API details of different LLM providers and client applications.

In an MCP workflow:
1.  **You run an MCP Server**: This server (like the one in this repo) hosts the tools.
2.  **Client connects**: An MCP Client (like Claude Desktop, Cursor, or VS Code extensions) connects to the server.
3.  **Standardized discovery**: The client automatically discovers available tools via the MCP protocol.
4.  **Seamless execution**: When the user chats with the model in the client, the client handles the tool calling loop (sending schema, executing tool, returning result) automatically.

## Comparison

| Feature | Function Calling | MCP Tool |
| :--- | :--- | :--- |
| **Integration Level** | Low-level API feature | High-level Protocol |
| **Setup** | Requires writing code to manage the loop (define schema, parse response, execute, feed back) | Plug-and-play with MCP clients; Server logic uses decorators |
| **Portability** | specific to the LLM API (e.g., OpenAI format) | Standardized across any MCP-compliant client/model |
| **Control** | Full control over the execution loop and state | delegated to the MCP Client |
| **User Interface** | You build the UI (or CLI) | Existing clients (Claude Desktop, etc.) provide the UI |

## When to use Function Calling?

You might prefer the **Function Calling** implementation (e.g., `server/secops/secops_mcp/tools/list_rules_function_calling.py`) when:

1.  **Building Custom Agents**: You are writing your own Python application using the OpenAI SDK (or similar) and need direct access to the tool definitions to pass to `client.chat.completions.create()`.
2.  **No MCP Client**: You are not using an MCP-compatible interface (like Claude Desktop) and are instead interacting with the model programmatically.
3.  **Custom Execution Logic**: You need to intercept the tool call, modify arguments, require human approval before execution, or chain multiple tools in a specific way that the standard MCP client doesn't support.

## When to use MCP Tools?

You should use the **MCP Tool** implementation (e.g., `server/secops/secops_mcp/tools/security_rules.py`) when:

1.  **Using Claude Desktop / IDEs**: You want to give the AI assistant in your IDE or Desktop app access to your security tools without writing any glue code.
2.  **Standardization**: You want a solution that works across different tools and clients that support MCP.

## Example: List Rules

We provide two versions of the "List Security Rules" functionality:

1.  **MCP Version** (`security_rules.py`):
    ```python
    @server.tool()
    async def list_security_rules(...):
        ...
    ```
    *Use this when running the `secops_mcp` server.*

2.  **Function Calling Version** (`list_rules_function_calling.py`):
    ```python
    LIST_RULES_SCHEMA = { ... }

    async def execute_list_rules_tool(arguments):
        ...
    ```
    *Use this when importing the tool into your own OpenAI API script.*
