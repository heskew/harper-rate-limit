// Mock Harper's global Resource class before any imports
globalThis.Resource = class Resource {
	static loadAsInstance = false;
};
