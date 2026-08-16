// https://docs.expo.dev/guides/using-eslint/
const { defineConfig } = require('eslint/config');
const expoConfig = require("eslint-config-expo/flat");

module.exports = defineConfig([
  expoConfig,
  {
    ignores: ["dist/*"],
  },
  {
    files: ["app/**/*.tsx", "src/**/*.tsx"],
    rules: {
      /**
       * BANS `style={({ pressed }) => …}`.
       *
       * React Native supports a function-valued `style` on `Pressable`, and
       * this app cannot use it. `babel.config.js` sets NativeWind's
       * `jsxImportSource`, which routes EVERY element through
       * `react-native-css-interop`; that runtime treats `style` as a source of
       * inline CSS rules and spreads it (`{...style}`), which for a function is
       * `{}`. The empty object is then assigned over the prop, so the function
       * is never called and whatever it returned is gone.
       *
       * It fails silently and it fails in proportion to how much the function
       * was carrying. `ui/Chip` lost a press fade nobody would file a bug
       * about; `QuickFilterBar`'s pills lost their entire layout and shipped
       * as unstyled stacked text for a day.
       *
       * Use a plain style OBJECT for layout, and `active:` classes for the
       * press state — or `ui/PressableScale`, which is the app's standard.
       */
      "no-restricted-syntax": [
        "error",
        {
          selector:
            "JSXAttribute[name.name='style'] > JSXExpressionContainer > :matches(ArrowFunctionExpression, FunctionExpression)",
          message:
            "A function-valued `style` is silently discarded by NativeWind's interop. Use a style object plus an `active:` class, or ui/PressableScale.",
        },
      ],
    },
  },
]);
