const { resolve: resolvePath } = require('path');
const { readdir } = require('fs').promises;
const isPermissionError = require('./isPermissionError');

/**
 *
 * @param dir
 * @param recursive
 */
async function getFiles(dir, recursive = true) {
    let items;

    try {
        items = await readdir(dir, { withFileTypes: true });
    } catch (err) {
        if (isPermissionError(err)) {
            console.warn(`Skipping directory "${dir}" due to permission error.`);
            return [];
        }
        throw err;
    }

    const filePromises = items.map(async (item) => {
        const fullPath = resolvePath(dir, item.name);

        if (!recursive && item.isDirectory()) {
            return null;
        }

        if (item.isDirectory()) {
            try {
                const subitems = await readdir(fullPath, { withFileTypes: true });
                if (subitems.length === 0) {
                    return [];
                }

                return await getFiles(fullPath, true);
            } catch (err) {
                if (isPermissionError(err)) {
                    console.warn(`Skipping subdirectory "${fullPath}" due to permission error.`);
                    return null;
                }
                throw err;
            }
        } else {
            return fullPath;
        }
    });

    const results = await Promise.all(filePromises);

    return results.filter(Boolean).flat();
}

module.exports = getFiles;
