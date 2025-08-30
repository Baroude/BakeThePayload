# ABOUTME: Tree-sitter queries for Python code analysis
# ABOUTME: Static query patterns for functions, calls, assignments, and classes

FUNCTION_DEFINITIONS = """
(function_definition
  name: (identifier) @function.name
  parameters: (parameters) @function.params
  body: (block) @function.body) @function.definition
"""

METHOD_DEFINITIONS = """
(function_definition
  name: (identifier) @method.name
  parameters: (parameters
    (identifier) @method.self
    (identifier)* @method.params)
  body: (block) @method.body) @method.definition
"""

FUNCTION_CALLS = """
(call
  (identifier) @call.name
  (argument_list) @call.args) @call.expression
"""

ATTRIBUTE_CALLS = """
(call
  (attribute
    object: (identifier) @call.object
    attribute: (identifier) @call.method)
  (argument_list) @call.args) @call.expression
"""

CLASS_DEFINITIONS = """
(class_definition
  name: (identifier) @class.name
  body: (block) @class.body) @class.definition
"""

ASSIGNMENTS = """
(assignment
  left: (identifier) @assignment.target
  right: (_) @assignment.value) @assignment.statement
"""

IMPORT_STATEMENTS = """
(import_statement
  name: (dotted_name) @import.module) @import.statement
"""

FROM_IMPORT_STATEMENTS = """
(import_from_statement
  module_name: (dotted_name) @import.module
  name: (dotted_name) @import.name) @import.statement
"""

VARIABLE_USAGE = """
(identifier) @variable.usage
"""

ALL_CALLS = f"""
{FUNCTION_CALLS}

{ATTRIBUTE_CALLS}
"""

# Composite queries for context extraction
FUNCTION_WITH_CALLS = f"""
{FUNCTION_DEFINITIONS}

{ALL_CALLS}
"""

CLASS_WITH_METHODS = f"""
{CLASS_DEFINITIONS}

{METHOD_DEFINITIONS}
"""
