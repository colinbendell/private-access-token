import js from "@eslint/js";
import jsdoc from 'eslint-plugin-jsdoc';

export default [
    {
        ...js.configs.recommended,
        ...jsdoc.configs['flat/recommended'],
        // "extends": [
        //   "eslint:recommended",
        //   "eslint-config-google"
        // ],
        plugins: {
            jsdoc,
        },
        rules: {
            indent: [ "error", 4 ],
            "brace-style": [ "error", "stroustrup" ],
            // "max-len": [ "error", 150 ],
            "jsdoc/require-description": "error",
            "arrow-parens": [ "error", "as-needed" ]
        },
        languageOptions: {
            sourceType: "module",
            ecmaVersion: "latest",
        }
    }
]
