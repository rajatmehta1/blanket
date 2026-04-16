"""Python entity extractor — classes, functions, calls, imports, entry points."""
from __future__ import annotations

from typing import Any

import structlog

from blanketaudit2.ingestion.extractors.base_extractor import BaseExtractor, ExtractionResult
from blanketaudit2.ingestion.models import (
    CallInfo,
    ClassInfo,
    EntryPointInfo,
    ImportInfo,
    MethodInfo,
)

logger = structlog.get_logger()

# Python branch node types for complexity counting
_BRANCH_TYPES = {"if_statement", "elif_clause", "for_statement", "while_statement",
                 "except_clause", "with_statement", "assert_statement",
                 "conditional_expression", "boolean_operator"}

# FastAPI/Flask/Django entry point decorators
_ENTRY_POINT_DECORATORS = {
    "app.get", "app.post", "app.put", "app.delete", "app.patch",
    "router.get", "router.post", "router.put", "router.delete", "router.patch",
    "app.route", "api_view",
}

_DECORATOR_TO_HTTP_METHOD = {
    "get": "GET", "post": "POST", "put": "PUT", "delete": "DELETE",
    "patch": "PATCH", "route": "",
}


class PythonExtractor(BaseExtractor):
    """Extract entities from Python source files using tree-sitter."""

    def extract(self, file_path: str, tree: Any, source: bytes) -> ExtractionResult:
        result = ExtractionResult(file_path, self.repo_name)
        root = tree.root_node
        self._extract_imports(root, source, result)
        self._extract_classes(root, source, result, parent_class=None)
        self._extract_functions(root, source, result, parent_class=None)
        return result

    def _extract_imports(self, node: Any, source: bytes, result: ExtractionResult) -> None:
        """Extract import and from...import statements."""
        for imp in self.walk_descendants(node, "import_statement"):
            module = self.node_text(imp, source).replace("import ", "").strip()
            result.imports.append(ImportInfo(
                source_file=result.file_path,
                imported_module=module.split(" as ")[0].strip(),
                line_number=self.node_line(imp),
            ))

        for imp in self.walk_descendants(node, "import_from_statement"):
            text = self.node_text(imp, source)
            is_relative = text.startswith("from .")
            # Extract module name
            module_node = self.find_first_child(imp, "dotted_name")
            if module_node is None:
                module_node = self.find_first_child(imp, "relative_import")
            module = self.node_text(module_node, source) if module_node else ""

            # Extract imported names
            names: list[str] = []
            for name_node in self.find_children(imp, "dotted_name"):
                if name_node != module_node:
                    names.append(self.node_text(name_node, source))
            # Also check for aliased imports
            for alias in self.find_children(imp, "aliased_import"):
                name = self.find_first_child(alias, "dotted_name")
                if name:
                    names.append(self.node_text(name, source))

            result.imports.append(ImportInfo(
                source_file=result.file_path,
                imported_module=module,
                imported_names=names,
                line_number=self.node_line(imp),
                is_relative=is_relative,
            ))

    def _get_decorators(self, node: Any, source: bytes) -> list[str]:
        """Extract decorator strings from a decorated definition."""
        decorators: list[str] = []
        for dec in self.find_children(node, "decorator"):
            text = self.node_text(dec, source).lstrip("@").strip()
            decorators.append(text)
        return decorators

    def _extract_classes(self, node: Any, source: bytes, result: ExtractionResult,
                          parent_class: str | None) -> None:
        """Extract class definitions."""
        # Handle both direct class_definition and decorated ones
        for child in node.children:
            cls_node = None
            decorators: list[str] = []

            if child.type == "class_definition":
                cls_node = child
            elif child.type == "decorated_definition":
                decorators = self._get_decorators(child, source)
                cls_node = self.find_first_child(child, "class_definition")

            if cls_node is None:
                continue

            name_node = self.find_first_child(cls_node, "identifier")
            if name_node is None:
                continue
            name = self.node_text(name_node, source)

            # Extract base classes
            bases: list[str] = []
            arg_list = self.find_first_child(cls_node, "argument_list")
            if arg_list:
                for arg in arg_list.children:
                    if arg.type == "identifier":
                        bases.append(self.node_text(arg, source))
                    elif arg.type == "attribute":
                        bases.append(self.node_text(arg, source))

            # Extract method names from body
            body = self.find_first_child(cls_node, "block")
            method_names: list[str] = []
            if body:
                for stmt in body.children:
                    func = None
                    if stmt.type == "function_definition":
                        func = stmt
                    elif stmt.type == "decorated_definition":
                        func = self.find_first_child(stmt, "function_definition")
                    if func:
                        fn_name = self.find_first_child(func, "identifier")
                        if fn_name:
                            method_names.append(self.node_text(fn_name, source))

            result.classes.append(ClassInfo(
                name=name,
                file_path=result.file_path,
                repo_name=result.repo_name,
                line_start=self.node_line(cls_node),
                line_end=self.node_end_line(cls_node),
                methods=method_names,
                bases=bases,
                decorators=decorators,
                loc=self.node_end_line(cls_node) - self.node_line(cls_node) + 1,
            ))

            # Extract methods inside the class
            if body:
                self._extract_functions(body, source, result, parent_class=name)

    def _extract_functions(self, node: Any, source: bytes, result: ExtractionResult,
                            parent_class: str | None) -> None:
        """Extract function/method definitions."""
        for child in node.children:
            func_node = None
            decorators: list[str] = []

            if child.type == "function_definition":
                func_node = child
            elif child.type == "decorated_definition":
                decorators = self._get_decorators(child, source)
                func_node = self.find_first_child(child, "function_definition")

            if func_node is None:
                continue

            name_node = self.find_first_child(func_node, "identifier")
            if name_node is None:
                continue
            name = self.node_text(name_node, source)
            qualified = f"{parent_class}.{name}" if parent_class else name

            # Extract parameters
            params: list[str] = []
            param_node = self.find_first_child(func_node, "parameters")
            if param_node:
                for p in param_node.children:
                    if p.type in ("identifier", "typed_parameter", "default_parameter",
                                   "typed_default_parameter", "list_splat_pattern",
                                   "dictionary_splat_pattern"):
                        params.append(self.node_text(p, source))

            # Return type
            return_type = ""
            ret_node = self.find_first_child(func_node, "type")
            if ret_node:
                return_type = self.node_text(ret_node, source)

            # Check for entry point decorators
            is_entry = False
            http_method = ""
            route = ""
            for dec in decorators:
                dec_lower = dec.split("(")[0].lower()
                if any(dec_lower.endswith(ep.split(".")[-1]) for ep in _ENTRY_POINT_DECORATORS):
                    is_entry = True
                    # Extract HTTP method from decorator name
                    for suffix, method in _DECORATOR_TO_HTTP_METHOD.items():
                        if dec_lower.endswith(suffix):
                            http_method = method
                            break
                    # Extract route from decorator args
                    if "(" in dec and '"' in dec:
                        route = dec.split('"')[1] if '"' in dec else ""
                    elif "(" in dec and "'" in dec:
                        route = dec.split("'")[1] if "'" in dec else ""
                    break

            # Complexity
            body = self.find_first_child(func_node, "block")
            complexity = self._count_complexity(body, _BRANCH_TYPES) if body else 1

            method = MethodInfo(
                name=name,
                qualified_name=qualified,
                file_path=result.file_path,
                repo_name=result.repo_name,
                line_start=self.node_line(func_node),
                line_end=self.node_end_line(func_node),
                parameters=params,
                return_type=return_type,
                decorators=decorators,
                is_entry_point=is_entry,
                loc=self.node_end_line(func_node) - self.node_line(func_node) + 1,
                complexity=complexity,
            )
            result.methods.append(method)

            if is_entry:
                result.entry_points.append(EntryPointInfo(
                    method_name=qualified,
                    file_path=result.file_path,
                    repo_name=result.repo_name,
                    http_method=http_method,
                    route=route,
                    framework="fastapi",
                    line_number=self.node_line(func_node),
                ))

            # Extract calls inside the function body
            if body:
                self._extract_calls(body, source, result, caller=qualified)

    def _extract_calls(self, node: Any, source: bytes, result: ExtractionResult,
                        caller: str) -> None:
        """Extract function calls within a node."""
        for call in self.walk_descendants(node, "call"):
            func = call.children[0] if call.children else None
            if func is None:
                continue
            callee = self.node_text(func, source)

            # Determine call type
            call_type = "direct"
            if "." in callee:
                call_type = "method"
            if callee[0].isupper() and "." not in callee:
                call_type = "constructor"
            if "await " in self.node_text(call, source):
                call_type = "async"

            result.calls.append(CallInfo(
                caller=caller,
                callee=callee,
                file_path=result.file_path,
                line_number=self.node_line(call),
                call_type=call_type,
            ))
