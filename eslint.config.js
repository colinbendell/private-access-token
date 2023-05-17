import js from "@eslint/js";

export default [
  {
    ...js.configs.recommended,
    // "extends": [
    //   "eslint:recommended",
    //   "eslint-config-google"
    // ],
    "rules": {
      "indent": [ "error", 4 ],
      "brace-style": [ "error", "stroustrup" ],
      // "max-len": [ "error", 125 ],
      "require-jsdoc": "error",
      "valid-jsdoc": "error",
      "arrow-parens": [ "error", "as-needed" ]
    },
    "languageOptions": {
      "sourceType": "module",
      "ecmaVersion": "latest",
    }
  }
]
