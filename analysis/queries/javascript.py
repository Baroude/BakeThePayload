# ABOUTME: Tree-sitter queries for JavaScript code analysis
# ABOUTME: Static query patterns for functions, calls, assignments, and classes

FUNCTION_DECLARATIONS = """
(function_declaration
  name: (identifier) @function.name
  parameters: (formal_parameters) @function.params
  body: (statement_block) @function.body) @function.definition
"""

FUNCTION_CALLS = """
(call_expression
  function: (identifier) @call.name
  arguments: (arguments) @call.args) @call.expression
"""

METHOD_CALLS = """
(call_expression
  function: (member_expression
    object: (identifier) @call.object
    property: (property_identifier) @call.method)
  arguments: (arguments) @call.args) @call.expression
"""

CLASS_DECLARATIONS = """
(class_declaration
  name: (identifier) @class.name
  body: (class_body) @class.body) @class.definition
"""

VARIABLE_DECLARATIONS = """
(variable_declarator
  name: (identifier) @variable.name
  value: (_)? @variable.value) @variable.declaration
"""

IMPORT_STATEMENTS = """
(import_statement
  source: (string) @import.source) @import.statement
"""

# Composite queries for context extraction
ALL_FUNCTIONS = f"""
{FUNCTION_DECLARATIONS}
"""

ALL_CALLS = f"""
{FUNCTION_CALLS}

{METHOD_CALLS}
"""
