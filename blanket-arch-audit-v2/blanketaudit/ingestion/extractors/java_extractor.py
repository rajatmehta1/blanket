"""Java entity extractor — classes, methods, calls, imports, Spring entry points."""
from __future__ import annotations
from typing import Any
import structlog
from blanketaudit.ingestion.extractors.base_extractor import BaseExtractor, ExtractionResult
from blanketaudit.ingestion.models import (
    CallInfo, ClassInfo, EntryPointInfo, ImportInfo, MethodInfo,
)

logger = structlog.get_logger()

_BRANCH_TYPES = {"if_statement", "for_statement", "while_statement", "do_statement",
                 "catch_clause", "switch_expression", "ternary_expression",
                 "binary_expression"}  # && and || count

_SPRING_ANNOTATIONS = {
    "GetMapping": "GET", "PostMapping": "POST", "PutMapping": "PUT",
    "DeleteMapping": "DELETE", "PatchMapping": "PATCH",
    "RequestMapping": "",
}

class JavaExtractor(BaseExtractor):
    def extract(self, file_path: str, tree: Any, source: bytes) -> ExtractionResult:
        result = ExtractionResult(file_path, self.repo_name)
        root = tree.root_node
        self._extract_imports(root, source, result)
        self._extract_classes(root, source, result)
        return result

    def _extract_imports(self, node: Any, source: bytes, result: ExtractionResult) -> None:
        for imp in self.walk_descendants(node, "import_declaration"):
            text = self.node_text(imp, source)
            module = text.replace("import ", "").replace("static ", "").rstrip(";").strip()
            result.imports.append(ImportInfo(
                source_file=result.file_path,
                imported_module=module,
                line_number=self.node_line(imp),
            ))

    def _get_annotations(self, node: Any, source: bytes) -> list[str]:
        annotations = []
        # Check siblings before the node (modifiers)
        for child in node.children:
            if child.type in ("modifiers", "annotation"):
                for ann in self.walk_descendants(child, "marker_annotation"):
                    annotations.append(self.node_text(ann, source).lstrip("@"))
                for ann in self.walk_descendants(child, "annotation"):
                    annotations.append(self.node_text(ann, source).lstrip("@"))
        return annotations

    def _extract_classes(self, node: Any, source: bytes, result: ExtractionResult) -> None:
        for cls_node in self.walk_descendants(node, "class_declaration"):
            name_node = self.find_first_child(cls_node, "identifier")
            if not name_node:
                continue
            name = self.node_text(name_node, source)

            # Bases (extends/implements)
            bases = []
            for super_cls in self.walk_descendants(cls_node, "superclass"):
                for ident in self.walk_descendants(super_cls, "type_identifier"):
                    bases.append(self.node_text(ident, source))
            for iface in self.walk_descendants(cls_node, "super_interfaces"):
                for ident in self.walk_descendants(iface, "type_identifier"):
                    bases.append(self.node_text(ident, source))

            annotations = self._get_annotations(cls_node, source)

            # Extract methods
            body = self.find_first_child(cls_node, "class_body")
            method_names = []
            if body:
                for method in self.walk_descendants(body, "method_declaration"):
                    mn = self.find_first_child(method, "identifier")
                    if mn:
                        method_names.append(self.node_text(mn, source))

            result.classes.append(ClassInfo(
                name=name,
                file_path=result.file_path,
                repo_name=result.repo_name,
                line_start=self.node_line(cls_node),
                line_end=self.node_end_line(cls_node),
                methods=method_names,
                bases=bases,
                decorators=annotations,
                loc=self.node_end_line(cls_node) - self.node_line(cls_node) + 1,
            ))

            if body:
                self._extract_methods(body, source, result, parent_class=name)

        # Also handle interface_declaration
        for iface in self.walk_descendants(node, "interface_declaration"):
            name_node = self.find_first_child(iface, "identifier")
            if not name_node:
                continue
            name = self.node_text(name_node, source)
            result.classes.append(ClassInfo(
                name=name,
                file_path=result.file_path,
                repo_name=result.repo_name,
                line_start=self.node_line(iface),
                line_end=self.node_end_line(iface),
                decorators=self._get_annotations(iface, source),
                loc=self.node_end_line(iface) - self.node_line(iface) + 1,
            ))

    def _extract_methods(self, body: Any, source: bytes, result: ExtractionResult,
                          parent_class: str) -> None:
        for method in self.walk_descendants(body, "method_declaration"):
            name_node = self.find_first_child(method, "identifier")
            if not name_node:
                continue
            name = self.node_text(name_node, source)
            qualified = f"{parent_class}.{name}"

            # Parameters
            params = []
            fp = self.find_first_child(method, "formal_parameters")
            if fp:
                for param in self.walk_descendants(fp, "formal_parameter"):
                    params.append(self.node_text(param, source))

            # Return type
            return_type = ""
            for child in method.children:
                if child.type in ("void_type", "type_identifier", "generic_type",
                                  "array_type", "integral_type", "floating_point_type",
                                  "boolean_type"):
                    return_type = self.node_text(child, source)
                    break

            annotations = self._get_annotations(method, source)

            # Entry point detection (Spring)
            is_entry = False
            http_method = ""
            route = ""
            for ann in annotations:
                ann_name = ann.split("(")[0]
                if ann_name in _SPRING_ANNOTATIONS:
                    is_entry = True
                    http_method = _SPRING_ANNOTATIONS[ann_name]
                    if "(" in ann and '"' in ann:
                        route = ann.split('"')[1]
                    break

            # Complexity
            meth_body = self.find_first_child(method, "block")
            complexity = self._count_complexity(meth_body, _BRANCH_TYPES) if meth_body else 1

            result.methods.append(MethodInfo(
                name=name,
                qualified_name=qualified,
                file_path=result.file_path,
                repo_name=result.repo_name,
                line_start=self.node_line(method),
                line_end=self.node_end_line(method),
                parameters=params,
                return_type=return_type,
                decorators=annotations,
                is_entry_point=is_entry,
                loc=self.node_end_line(method) - self.node_line(method) + 1,
                complexity=complexity,
            ))

            if is_entry:
                result.entry_points.append(EntryPointInfo(
                    method_name=qualified,
                    file_path=result.file_path,
                    repo_name=result.repo_name,
                    http_method=http_method,
                    route=route,
                    framework="spring",
                    line_number=self.node_line(method),
                ))

            # Extract calls
            if meth_body:
                self._extract_calls(meth_body, source, result, caller=qualified)

        # Constructor declarations
        for ctor in self.walk_descendants(body, "constructor_declaration"):
            name_node = self.find_first_child(ctor, "identifier")
            if not name_node:
                continue
            name = self.node_text(name_node, source)
            qualified = f"{parent_class}.{name}"
            result.methods.append(MethodInfo(
                name=name,
                qualified_name=qualified,
                file_path=result.file_path,
                repo_name=result.repo_name,
                line_start=self.node_line(ctor),
                line_end=self.node_end_line(ctor),
                loc=self.node_end_line(ctor) - self.node_line(ctor) + 1,
                complexity=1,
            ))

    def _extract_calls(self, node: Any, source: bytes, result: ExtractionResult,
                        caller: str) -> None:
        for call in self.walk_descendants(node, "method_invocation"):
            callee = self.node_text(call, source).split("(")[0]
            call_type = "method" if "." in callee else "direct"
            result.calls.append(CallInfo(
                caller=caller,
                callee=callee,
                file_path=result.file_path,
                line_number=self.node_line(call),
                call_type=call_type,
            ))
        for obj_creation in self.walk_descendants(node, "object_creation_expression"):
            type_node = self.find_first_child(obj_creation, "type_identifier")
            if type_node:
                result.calls.append(CallInfo(
                    caller=caller,
                    callee=self.node_text(type_node, source),
                    file_path=result.file_path,
                    line_number=self.node_line(obj_creation),
                    call_type="constructor",
                ))
