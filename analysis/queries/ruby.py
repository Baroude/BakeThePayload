# ABOUTME: Tree-sitter queries for Ruby code analysis
# ABOUTME: Static query patterns for methods, calls, assignments, and classes

METHOD_DEFINITIONS = """
(method
  name: (identifier) @method.name
  parameters: (method_parameters)? @method.params
  body: (_) @method.body) @method.definition
"""

CLASS_DEFINITIONS = """
(class
  name: (constant) @class.name
  superclass: (superclass)? @class.extends
  body: (_) @class.body) @class.definition
"""

MODULE_DEFINITIONS = """
(module
  name: (constant) @module.name
  body: (_) @module.body) @module.definition
"""

METHOD_CALLS = """
(call
  method: (identifier) @call.name
  arguments: (argument_list)? @call.args) @call.expression
"""

ATTRIBUTE_CALLS = """
(call
  receiver: (identifier) @call.object
  method: (identifier) @call.method
  arguments: (argument_list)? @call.args) @call.expression
"""

ASSIGNMENTS = """
(assignment
  left: (identifier) @assignment.target
  right: (_) @assignment.value) @assignment.statement
"""

CONSTANT_ASSIGNMENTS = """
(assignment
  left: (constant) @assignment.target
  right: (_) @assignment.value) @assignment.statement
"""

INSTANCE_VARIABLE_ASSIGNMENTS = """
(assignment
  left: (instance_variable) @assignment.target
  right: (_) @assignment.value) @assignment.statement
"""

REQUIRE_STATEMENTS = """
(call
  method: (identifier) @require.method
  arguments: (argument_list
    (string) @require.path)) @require.statement
(#eq? @require.method "require")
"""

# Composite queries for context extraction
ALL_DEFINITIONS = f"""
{METHOD_DEFINITIONS}

{CLASS_DEFINITIONS}

{MODULE_DEFINITIONS}
"""

ALL_CALLS = f"""
{METHOD_CALLS}

{ATTRIBUTE_CALLS}
"""

ALL_ASSIGNMENTS = f"""
{ASSIGNMENTS}

{CONSTANT_ASSIGNMENTS}

{INSTANCE_VARIABLE_ASSIGNMENTS}
"""
