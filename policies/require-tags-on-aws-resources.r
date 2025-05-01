package spacelift

deny["AWS resources must have tags"] {
  input.resource_changes[_].type == "aws_instance"
  not input.resource_changes[_].change.after.tags
}
