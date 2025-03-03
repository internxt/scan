/// <reference types="node" />

import { Socket } from 'dgram';
import { Readable } from 'stream';

declare namespace NodeClam {
    interface ClamScanSettings {
        /** If true, removes infected files */
        removeInfected?: boolean;
        /** False: Don't quarantine, Path: Moves files to this place. */
        quarantineInfected?: boolean | string;
        /** Path to a writeable log file to write scan results into */
        scanLog?: string | null;
        /** Whether to log info/debug/error msg to the console */
        debugMode?: boolean;
        /** path to file containing list of files to scan (for scanFiles method) */
        fileList?: string | null;
        /** If true, deep scan folders recursively */
        scanRecursively?: boolean;
        clamscan?: {
            /** Path to clamscan binary on your server */
            path?: string;
            /** Path to a custom virus definition database */
            db?: string | null;
            /** If true, scan archives (ex. zip, rar, tar, dmg, iso, etc...) */
            scanArchives?: boolean;
            /** If true, this module will consider using the clamscan binary */
            active?: boolean;
        };
        clamdscan?: {
            /** Socket file for connecting via TCP */
            socket?: string | boolean;
            /** IP of host to connect to TCP interface */
            host?: string | boolean;
            /** Port of host to use when connecting via TCP interface */
            port?: number | boolean;
            /** Timeout for scanning files */
            timeout?: number;
            /** Do not fail over to binary-method of scanning */
            localFallback?: boolean;
            /** Path to the clamdscan binary on your server */
            path?: string;
            /** Specify config file if it's in an unusual place */
            configFile?: string | null;
            /** Scan using all available cores! Yay! */
            multiscan?: boolean;
            /** If true, will re-load the DB on every call (slow) */
            reloadDb?: boolean;
            /** If true, this module will consider using the clamdscan binary */
            active?: boolean;
            /** Check to see if socket is available when applicable */
            bypassTest?: boolean;
            /** If true, connect to a TLS-Termination proxy in front of ClamAV */
            tls?: boolean;
        };
        /** If clamdscan is found and active, it will be used by default */
        preference?: any;
    }

    interface ScanResult {
        file: string;
        isInfected: boolean;
        viruses: string[];
        resultString?: string;
        timeout?: boolean;
    }

    interface ScanFileResult extends ScanResult {
        viruses: string[];
        file: string;
        isInfected: boolean;
    }

    interface FileScanResult {
        [filePath: string]: {
            isInfected: boolean;
            viruses: string[];
        };
    }

    interface ScanDirResult {
        path: string;
        isInfected: boolean;
        goodFiles: string[];
        goodFileCount: number;
        infectedFiles: FileScanResult;
        infectedFileCount: number;
        error: Error | null;
        errorFiles: string[];
        errorFileCount: number;
        files: FileScanResult;
        fileCount: number;
    }

    interface ScanBufferResult extends ScanResult {
        isInfected: boolean;
        viruses: string[];
    }

    interface ScanStreamResult extends ScanResult {
        isInfected: boolean;
        viruses: string[];
    }

    // Create a union type that combines ClamScanner and NodeClam functionality
    interface ClamScanner {
        scanFile: (filePath: string) => Promise<ScanFileResult>;
        scanDir: (
            directoryPath: string,
            endCallback?: (err: Error | null, goodFiles?: string[], badFiles?: string[], viruses?: string[]) => void,
            fileCallback?: (err: Error | null, file?: string, isInfected?: boolean, viruses?: string[], scannedCount?: number, progress?: string) => void
        ) => Promise<ScanDirResult>;
        scanFiles: (
            files: string[] | string,
            endCallback?: (err: Error | null, goodFiles?: string[], badFiles?: string[], errors?: object, viruses?: string[]) => void,
            fileCallback?: (err: Error | null, file?: string, isInfected?: boolean, viruses?: string[], scannedCount?: number, progress?: string) => void
        ) => Promise<{goodFiles: string[], badFiles: string[], errors: object, viruses: string[]}>;
        scanStream: (stream: Readable) => Promise<ScanStreamResult>;
        getVersion: (cb?: (err: Error | null, version: string) => void) => Promise<string>;
        isInfected: (file: string) => Promise<ScanFileResult>;
        passthrough: () => ClamScanner;
        /**
         * Closes all active socket connections tracked by the scanner
         * @returns A promise that resolves when all sockets have been closed
         */
        closeAllSockets: () => Promise<string>;
        
        /**
         * Quick check to see if the remote/local socket is working
         * @param cb - Optional callback function to handle the result
         * @returns A Promise that resolves with a Socket client instance
         */
        ping: (cb?: (err: Error | null, client: Socket | null) => void) => Promise<Socket>;

        /**
         * Initialize the NodeClam instance
         * @param settings - Configuration settings 
         * @param cb - Optional callback function
         * @returns The initialized NodeClam instance
         */
        init: (settings?: ClamScanSettings, cb?: (err: Error | null, instance: any) => void) => Promise<ClamScanner>;

        /**
         * Reset and reinitialize the NodeClam instance with new options
         * @param options - New configuration settings
         * @param cb - Optional callback function
         * @returns The reset NodeClam instance
         */
        reset: (options?: ClamScanSettings, cb?: (err: Error | null, instance: any) => void) => Promise<ClamScanner>;
    }
}

declare class NodeClam {
    /**
     * Initialize the NodeClam instance
     * @param settings - Configuration settings
     * @param cb - Optional callback function
     * @returns The initialized NodeClam instance with all scanning capabilities
     */
    init(settings?: NodeClam.ClamScanSettings, cb?: (err: Error | null, instance: NodeClam) => void): Promise<NodeClam.ClamScanner>;

    /**
     * Reset and reinitialize the NodeClam instance with new options
     * @param options - New configuration settings
     * @param cb - Optional callback function
     * @returns The reset NodeClam instance
     */
    reset(options?: NodeClam.ClamScanSettings, cb?: (err: Error | null, instance: NodeClam) => void): Promise<NodeClam.ClamScanner>;

    /**
     * Scan a file for viruses
     * @param filePath - The path to the file to be scanned
     * @returns Scan results
     */
    scanFile(filePath: string): Promise<NodeClam.ScanFileResult>;

    /**
     * Scan a directory for viruses
     * @param directoryPath - The path to the directory to be scanned
     * @param endCallback - Optional callback function for when scanning is complete
     * @param fileCallback - Optional callback function for each scanned file
     * @returns Scan results
     */
    scanDir(
        directoryPath: string,
        endCallback?: (err: Error | null, goodFiles?: string[], badFiles?: string[], viruses?: string[]) => void,
        fileCallback?: (err: Error | null, file?: string, isInfected?: boolean, viruses?: string[], scannedCount?: number, progress?: string) => void
    ): Promise<NodeClam.ScanDirResult>;

    /**
     * Scan multiple files for viruses
     * @param files - Array of file paths to scan
     * @param endCallback - Optional callback function for when scanning is complete
     * @param fileCallback - Optional callback function for each scanned file
     * @returns Scan results
     */
    scanFiles(
        files: string[] | string,
        endCallback?: (err: Error | null, goodFiles?: string[], badFiles?: string[], errors?: object, viruses?: string[]) => void,
        fileCallback?: (err: Error | null, file?: string, isInfected?: boolean, viruses?: string[], scannedCount?: number, progress?: string) => void
    ): Promise<{goodFiles: string[], badFiles: string[], errors: object, viruses: string[]}>;

    /**
     * Scan a stream for viruses
     * @param stream - The readable stream to be scanned
     * @returns Scan results
     */
    scanStream(stream: Readable): Promise<NodeClam.ScanStreamResult>;

    /**
     * Get the version information
     * @param cb - Optional callback function
     * @returns Version information
     */
    getVersion(cb?: (err: Error | null, version: string) => void): Promise<string>;

    /**
     * Check if a file is infected
     * @param file - Path to the file to check
     * @returns Scan results
     */
    isInfected(file: string): Promise<NodeClam.ScanFileResult>;

    /**
     * Quick check to see if the remote/local socket is working
     * @param cb - Optional callback function
     * @returns A Promise that resolves with a Socket client instance
     */
    ping(cb?: (err: Error | null, client: Socket | null) => void): Promise<Socket>;

    /**
     * Passthrough method to directly access the raw scanner
     * @returns The raw scanner object
     */
    passthrough(): NodeClam.ClamScanner;
    
    /**
     * Closes all active socket connections tracked by the scanner
     * @returns A promise that resolves when all sockets have been closed
     */
    closeAllSockets(): Promise<string>;
}

export = NodeClam;
