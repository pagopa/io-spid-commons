module.exports = {
    "env": {
        "es6": true,
        "node": true
    },
    "ignorePatterns": [
        "node_modules",
        "generated",
        "**/__tests__/*",
        "**/__mocks__/*",
        "Dangerfile.*",
        ".eslintrc.js",
        "*.d.ts"
    ],
    "parser": "@typescript-eslint/parser",
    "parserOptions": {
        "project": "tsconfig.json",
        "sourceType": "module"
    },
    "extends": [
        "@pagopa/eslint-config/strong",
    ],
    "rules": {
        "jsdoc/newline-after-description": "off",
        // this rule is a replacement for the above one which got removed but it's still
        // mentioned in @pagopa/eslint-config@3.0.0
        "jsdoc/tag-lines": ["error", "any", {"startLines": 1}]
    }
}
