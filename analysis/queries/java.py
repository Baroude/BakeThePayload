# ABOUTME: Tree-sitter queries for Java code analysis
# ABOUTME: Static query patterns for methods, calls, assignments, and classes

METHOD_DECLARATIONS = """
(method_declaration
  (modifiers)? @method.modifiers
  type: (_) @method.return_type
  name: (identifier) @method.name
  parameters: (formal_parameters) @method.params
  body: (block) @method.body) @method.definition
"""

CONSTRUCTOR_DECLARATIONS = """
(constructor_declaration
  (modifiers)? @constructor.modifiers
  name: (identifier) @constructor.name
  parameters: (formal_parameters) @constructor.params
  body: (constructor_body) @constructor.body) @constructor.definition
"""

METHOD_INVOCATIONS = """
(method_invocation
  object: (identifier)? @call.object
  name: (identifier) @call.name
  arguments: (argument_list) @call.args) @call.expression
"""

CLASS_DECLARATIONS = """
(class_declaration
  (modifiers)? @class.modifiers
  name: (identifier) @class.name
  superclass: (superclass)? @class.extends
  interfaces: (super_interfaces)? @class.implements
  body: (class_body) @class.body) @class.definition
"""

INTERFACE_DECLARATIONS = """
(interface_declaration
  (modifiers)? @interface.modifiers
  name: (identifier) @interface.name
  extends: (extends_interfaces)? @interface.extends
  body: (interface_body) @interface.body) @interface.definition
"""

FIELD_DECLARATIONS = """
(field_declaration
  (modifiers)? @field.modifiers
  type: (_) @field.type
  declarator: (variable_declarator
    name: (identifier) @field.name
    value: (_)? @field.value)) @field.declaration
"""

ASSIGNMENTS = """
(assignment_expression
  left: (identifier) @assignment.target
  right: (_) @assignment.value) @assignment.statement
"""

VARIABLE_DECLARATIONS = """
(local_variable_declaration
  type: (_) @variable.type
  declarator: (variable_declarator
    name: (identifier) @variable.name
    value: (_)? @variable.value)) @variable.declaration
"""

IMPORT_DECLARATIONS = """
(import_declaration
  (scoped_identifier)? @import.package
  (identifier) @import.class) @import.statement
"""

# Composite queries for context extraction
ALL_METHODS = f"""
{METHOD_DECLARATIONS}

{CONSTRUCTOR_DECLARATIONS}
"""

ALL_TYPES = f"""
{CLASS_DECLARATIONS}

{INTERFACE_DECLARATIONS}
"""