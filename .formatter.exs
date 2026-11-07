# Used by "mix format"
[
  inputs: ["{mix,.formatter}.exs", "{config,lib,test}/**/*.{ex,exs}"],
  # StreamData's, which can't be imported as it's a dependency for tests only.
  locals_without_parens: [
    all: :*,
    check: 1,
    check: 2,
    gen: 1,
    gen: 2,
    property: 1,
    property: 2,
    property: 3
  ]
]
