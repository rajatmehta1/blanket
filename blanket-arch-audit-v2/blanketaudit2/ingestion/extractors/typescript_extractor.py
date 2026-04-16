"""TypeScript/JavaScript entity extractor."""
from __future__ import annotations
from typing import Any
import structlog
from blanketaudit2.ingestion.extractors.base_extractor import BaseExtractor, ExtractionResult
from blanketaudit2.ingestion.models import (
    CallInfo, ClassInfo, EntryPointInfo, ImportInfo, MethodInfo,
)

logger = structlog.get_logger()

_BRANCH_TYPES = {"if_statement", "for_statement", "for_in_statement", "while_statement",
                 "do_statement", "switch_case", "catch_clause", "ternary_expression",
                 "binary_expression"}

_EXPRESS_METHODS = {"get", "post", "put", "delete", "patch", "all", "use"}

class TypeScriptExtractor(BaseExtractor):
    def extract(self, file_path: str, tree: Any, source: bytes) -> ExtractionResult:
        result = ExtractionResult(file_path, self.repo_name)
        root = tree.root_node
        self._extract_imports(root, source, result)
        self._extract_classes(root, source, result)
        self._extract_top_level_functions(root, source, result)
        self._extract_express_routes(root, source, result)
        return result

    def _extract_imports(self, node: Any, source: bytes, result: ExtractionResult) -> None:
        # ES6 imports: import { x } from 'module'
        for imp in self.walk_descendants(node, "import_statement"):
            text = self.node_text(imp, source)
            # Extract module from the string
            module = ""
            str_node = self.find_first_child(imp, "string")
            if str_node is None:
                # Try deeper
                for child in imp.children:
                    if child.type == "string":
                        str_node = child
                        break
            if str_node:
                module = self.node_text(str_node, source).strip("'\"")

            # Extract imported names
            names = []
            for spec in self.walk_descendants(imp, "import_specifier"):
                names.append(self.node_text(spec, source).split(" as ")[0].strip())

            result.imports.append(ImportInfo(
                source_file=result.file_path,
                imported_module=module,
                imported_names=names,
                line_number=self.node_line(imp),
                is_relative=module.startswith("."),
            ))

        # CommonJS: const x = require('module')
        for call in self.walk_descendants(node, "call_expression"):
            func = call.children[0] if call.children else None
            if func and self.node_text(func, source) == "require":
                args = self.find_first_child(call, "arguments")
                if args:
                    str_node = self.find_first_child(args, "string")
                    if str_node:
                        module = self.node_text(str_node, source).strip("'\"")
                        result.imports.append(ImportInfo(
                            source_file=result.file_path,
                            imported_module=module,
                            line_number=self.node_line(call),
                            is_relative=module.startswith("."),
                        ))

    def _extract_classes(self, node: Any, source: bytes, result: ExtractionResult) -> None:
        for cls in self.walk_descendants(node, "class_declaration"):
            name_node = self.find_first_child(cls, "type_identifier") or self.find_first_child(cls, "identifier")
            if not name_node:
                continue
            name = self.node_text(name_node, source)

            # Heritage (extends/implements)
            bases = []
            heritage = self.find_first_child(cls, "class_heritage")
            if heritage:
                for ident in self.walk_descendants(heritage, "type_identifier"):
                    bases.append(self.node_text(ident, source))
                for ident in self.walk_descendants(heritage, "identifier"):
                    bases.append(self.node_text(ident, source))

            # Methods
            body = self.find_first_child(cls, "class_body")
            method_names = []
            if body:
                for method in self.walk_descendants(body, "method_definition"):
                    mn = self.find_first_child(method, "property_identifier")
                    if mn:
                        method_names.append(self.node_text(mn, source))

            result.classes.append(ClassInfo(
                name=name,
                file_path=result.file_path,
                repo_name=result.repo_name,
                line_start=self.node_line(cls),
                line_end=self.node_end_line(cls),
                methods=method_names,
                bases=bases,
                loc=self.node_end_line(cls) - self.node_line(cls) + 1,
            ))

            # Extract methods
            if body:
                self._extract_class_methods(body, source, result, parent_class=name)

    def _extract_class_methods(self, body: Any, source: bytes, result: ExtractionResult,
                                parent_class: str) -> None:
        for method in self.walk_descendants(body, "method_definition"):
            name_node = self.find_first_child(method, "property_identifier")
            if not name_node:
                continue
            name = self.node_text(name_node, source)
            qualified = f"{parent_class}.{name}"

            params = []
            fp = self.find_first_child(method, "formal_parameters")
            if fp:
                for p in fp.children:
                    if p.type in ("required_parameter", "optional_parameter", "identifier"):
                        params.append(self.node_text(p, source))

            meth_body = self.find_first_child(method, "statement_block")
            complexity = self._count_complexity(meth_body, _BRANCH_TYPES) if meth_body else 1

            result.methods.append(MethodInfo(
                name=name,
                qualified_name=qualified,
                file_path=result.file_path,
                repo_name=result.repo_name,
                line_start=self.node_line(method),
                line_end=self.node_end_line(method),
                parameters=params,
                loc=self.node_end_line(method) - self.node_line(method) + 1,
                complexity=complexity,
            ))

            if meth_body:
                self._extract_calls(meth_body, source, result, caller=qualified)

    def _extract_top_level_functions(self, node: Any, source: bytes, result: ExtractionResult) -> None:
        for func in node.children:
            if func.type == "function_declaration":
                name_node = self.find_first_child(func, "identifier")
                if not name_node:
                    continue
                name = self.node_text(name_node, source)

                params = []
                fp = self.find_first_child(func, "formal_parameters")
                if fp:
                    for p in fp.children:
                        if p.type in ("required_parameter", "optional_parameter", "identifier"):
                            params.append(self.node_text(p, source))

                body = self.find_first_child(func, "statement_block")
                complexity = self._count_complexity(body, _BRANCH_TYPES) if body else 1

                result.methods.append(MethodInfo(
                    name=name,
                    qualified_name=name,
                    file_path=result.file_path,
                    repo_name=result.repo_name,
                    line_start=self.node_line(func),
                    line_end=self.node_end_line(func),
                    parameters=params,
                    loc=self.node_end_line(func) - self.node_line(func) + 1,
                    complexity=complexity,
                ))

                if body:
                    self._extract_calls(body, source, result, caller=name)

            # export function / export default function
            elif func.type == "export_statement":
                inner = self.find_first_child(func, "function_declaration")
                if inner:
                    name_node = self.find_first_child(inner, "identifier")
                    if name_node:
                        name = self.node_text(name_node, source)
                        body = self.find_first_child(inner, "statement_block")
                        result.methods.append(MethodInfo(
                            name=name,
                            qualified_name=name,
                            file_path=result.file_path,
                            repo_name=result.repo_name,
                            line_start=self.node_line(inner),
                            line_end=self.node_end_line(inner),
                            loc=self.node_end_line(inner) - self.node_line(inner) + 1,
                            complexity=1,
                        ))

    def _extract_express_routes(self, node: Any, source: bytes, result: ExtractionResult) -> None:
        """Detect Express.js route handlers like app.get('/path', handler)."""
        for call in self.walk_descendants(node, "call_expression"):
            func = call.children[0] if call.children else None
            if func is None or func.type != "member_expression":
                continue
            text = self.node_text(func, source)
            parts = text.rsplit(".", 1)
            if len(parts) != 2:
                continue
            obj, method = parts
            if method.lower() not in _EXPRESS_METHODS:
                continue

            # Get route from first string arg
            args = self.find_first_child(call, "arguments")
            route = ""
            if args:
                str_node = self.find_first_child(args, "string")
                if str_node:
                    route = self.node_text(str_node, source).strip("'\"")

            if route:
                result.entry_points.append(EntryPointInfo(
                    method_name=f"{obj}.{method}",
                    file_path=result.file_path,
                    repo_name=result.repo_name,
                    http_method=method.upper() if method.lower() != "use" else "",
                    route=route,
                    framework="express",
                    line_number=self.node_line(call),
                ))

    def _extract_calls(self, node: Any, source: bytes, result: ExtractionResult,
                        caller: str) -> None:
        for call in self.walk_descendants(node, "call_expression"):
            func = call.children[0] if call.children else None
            if func is None:
                continue
            callee = self.node_text(func, source)
            call_type = "method" if "." in callee else "direct"
            if callee == "new":
                call_type = "constructor"
            result.calls.append(CallInfo(
                caller=caller,
                callee=callee,
                file_path=result.file_path,
                line_number=self.node_line(call),
                call_type=call_type,
            ))
