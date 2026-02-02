import harperdbConfig from '@harperdb/code-guidelines/eslint';

export default [
	...harperdbConfig,
	{
		ignores: ['dist/**'],
		languageOptions: {
			parserOptions: {
				project: './tsconfig.json',
				tsconfigRootDir: import.meta.dirname,
			},
		},
	},
];
