const HttpError = require("../lib/http-error");

function validate(schema, source = "body") {
  return (req, _res, next) => {
    const result = schema.safeParse(req[source]);
    if (!result.success) {
      return next(
        new HttpError("validation", {
          status: 400,
          code: "validation",
          issues: result.error.issues,
        })
      );
    }
    req[source] = result.data;
    return next();
  };
}

module.exports = validate;
