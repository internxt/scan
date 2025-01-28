/**
 *
 * @param err
 */
function isPermissionError(err) {
    if (!err) return false;

    const msg = err.message?.toLowerCase() || '';

    return (
        err.code === 'EACCES' ||
        err.code === 'EPERM' ||
        err.code === 'EBUSY' ||
        err.code === 'ENOENT' ||
        err.code === 'ENOFILE' ||
        msg.includes('operation not permitted') ||
        msg.includes('access denied') ||
        msg.includes('access is denied')
    );
}

module.exports = isPermissionError;
