/* =========================================================
   RYANAIR FINANCIAL DASHBOARD
   SUPABASE DOCUMENT STORAGE
   =========================================================

   PURPOSE
   -------
   Supabase is used ONLY for physical document storage.

   Firebase remains responsible for:
       - Authentication
       - Users
       - Roles
       - Permissions
       - Contract metadata
       - Logs
       - Application data

   Supabase is responsible for:
       - Contract files
       - Document upload
       - Document download
       - Document deletion
       - Document movement
       - Document URLs

   STORAGE
   -------
   Bucket:
       Financial Documents

   Root:
       financial-dashboard/

   Example:

       financial-dashboard/
       └── contracts/
           └── CONTRACT_ID/
               ├── FILE_ID_document.pdf
               └── FILE_ID_document2.pdf

========================================================= */


/* =========================================================
   SUPABASE SDK
========================================================= */

import {
    createClient
} from
    "https://cdn.jsdelivr.net/npm/@supabase/supabase-js@2/+esm";


/* =========================================================
   SUPABASE PROJECT CONFIGURATION
========================================================= */

const SUPABASE_URL =
    "https://tcunbqqoebaerfqukjuh.supabase.co";


const SUPABASE_PUBLISHABLE_KEY =
    "sb_publishable_wQdnVdHjcRBWJj5Zn3kGMA_ob-DAXA2";


/* =========================================================
   STORAGE CONFIGURATION
========================================================= */

const SUPABASE_STORAGE = {

    /*
        Supabase Storage bucket.
    */

    bucket:
        "Financial Documents",


    /*
        Root folder belonging to this application.
    */

    root:
        "financial-dashboard",


    /*
        Contract documents root.
    */

    contractsRoot:
        "financial-dashboard/contracts",


    /*
        Maximum file size.

        This is an application-side safety check.
        Supabase policies can impose additional limits.
    */

    maxFileSize:
        50 * 1024 * 1024,


    /*
        Allowed document types.

        This list can be expanded later if necessary.
    */

    allowedMimeTypes: [

        "application/pdf",

        "application/msword",

        "application/vnd.openxmlformats-officedocument.wordprocessingml.document",

        "application/vnd.ms-excel",

        "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",

        "application/vnd.ms-powerpoint",

        "application/vnd.openxmlformats-officedocument.presentationml.presentation",

        "text/plain",

        "image/jpeg",

        "image/png",

        "image/webp"

    ]

};


/* =========================================================
   SUPABASE CLIENT
========================================================= */

const supabase =
    createClient(

        SUPABASE_URL,

        SUPABASE_PUBLISHABLE_KEY

    );


/* =========================================================
   SUPABASE STATUS
========================================================= */

const SUPABASE_STATUS = {

    initialized:
        true,

    provider:
        "supabase",

    purpose:
        "document-storage",

    bucket:
        SUPABASE_STORAGE.bucket,

    root:
        SUPABASE_STORAGE.root

};


/* =========================================================
   CLIENT ACCESS
========================================================= */

function getSupabase() {

    return supabase;

}


/* =========================================================
   STORAGE ACCESS
========================================================= */

function getSupabaseStorage() {

    return supabase.storage;

}


/* =========================================================
   DOCUMENT BUCKET
========================================================= */

function getDocumentBucket() {

    return supabase
        .storage
        .from(
            SUPABASE_STORAGE.bucket
        );

}


/* =========================================================
   FILE NAME SANITISATION
========================================================= */

function sanitizeFileName(
    fileName
) {

    let safeName =
        String(
            fileName || "document"
        )
            .trim();


    /*
        Remove characters that can cause problems
        in storage paths.
    */

    safeName =
        safeName.replace(
            /[<>:"/\\|?*\x00-\x1F]/g,
            "_"
        );


    /*
        Normalise whitespace.
    */

    safeName =
        safeName.replace(
            /\s+/g,
            "_"
        );


    /*
        Avoid an empty filename.
    */

    if (
        !safeName
    ) {

        safeName =
            "document";

    }


    /*
        Keep paths at a reasonable length.
    */

    return safeName.substring(
        0,
        180
    );

}


/* =========================================================
   CONTRACT ID SANITISATION
========================================================= */

function sanitizeStorageSegment(
    value
) {

    const segment =
        String(
            value || ""
        )
            .trim()
            .replace(
                /[^a-zA-Z0-9_-]/g,
                "_"
            );


    if (
        !segment
    ) {

        throw new Error(
            "Invalid storage path segment."
        );

    }


    return segment;

}


/* =========================================================
   BUILD CONTRACT DOCUMENT PATH
========================================================= */

/*
    Creates the definitive storage path for a contract file.

    Example:

        financial-dashboard/contracts/
        CONTRACT-001/
        FILE-123_contract.pdf
*/

function buildContractDocumentPath(

    contractId,

    fileId,

    fileName

) {

    const safeContractId =
        sanitizeStorageSegment(
            contractId
        );


    const safeFileId =
        sanitizeStorageSegment(
            fileId
        );


    const safeFileName =
        sanitizeFileName(
            fileName
        );


    return [

        SUPABASE_STORAGE.contractsRoot,

        safeContractId,

        `${safeFileId}_${safeFileName}`

    ].join("/");

}


/* =========================================================
   BUILD CONTRACT FOLDER PATH
========================================================= */

function buildContractFolderPath(
    contractId
) {

    const safeContractId =
        sanitizeStorageSegment(
            contractId
        );


    return [

        SUPABASE_STORAGE.contractsRoot,

        safeContractId

    ].join("/");

}


/* =========================================================
   VALIDATE FILE
========================================================= */

function validateDocumentFile(
    file
) {

    if (
        !file
    ) {

        throw new Error(
            "No document selected."
        );

    }


    /*
        File size validation.
    */

    if (
        file.size >
        SUPABASE_STORAGE.maxFileSize
    ) {

        const maxSizeMB =
            SUPABASE_STORAGE.maxFileSize /
            1024 /
            1024;


        throw new Error(

            `The selected file exceeds the ${maxSizeMB} MB limit.`

        );

    }


    /*
        MIME validation.

        Some browsers may provide an empty MIME type,
        so we only reject it when it is explicitly known
        and unsupported.
    */

    if (
        file.type &&
        !SUPABASE_STORAGE
            .allowedMimeTypes
            .includes(
                file.type
            )
    ) {

        throw new Error(

            `File type "${file.type}" is not supported.`

        );

    }


    return true;

}


/* =========================================================
   UPLOAD CONTRACT DOCUMENT
========================================================= */

/*
    Uploads the physical file only.

    Contract metadata remains in Firebase.

    Parameters:

        file
        storagePath

    Returns:

        Supabase upload response.
*/

async function uploadContractDocument(

    file,

    storagePath

) {

    validateDocumentFile(
        file
    );


    if (
        !storagePath
    ) {

        throw new Error(
            "No storage path specified."
        );

    }


    const bucket =
        getDocumentBucket();


    const {
        data,
        error
    } =
        await bucket.upload(

            storagePath,

            file,

            {

                cacheControl:
                    "3600",

                contentType:
                    file.type ||
                    "application/octet-stream",

                upsert:
                    false

            }

        );


    if (
        error
    ) {

        console.error(
            "SUPABASE — Upload failed:",
            error
        );


        throw error;

    }


    return data;

}


/* =========================================================
   REPLACE CONTRACT DOCUMENT
========================================================= */

/*
    Same as upload, but allows overwriting an existing file.

    This is useful later when a contract document is
    replaced by a newer version.
*/

async function replaceContractDocument(

    file,

    storagePath

) {

    validateDocumentFile(
        file
    );


    if (
        !storagePath
    ) {

        throw new Error(
            "No storage path specified."
        );

    }


    const bucket =
        getDocumentBucket();


    const {
        data,
        error
    } =
        await bucket.upload(

            storagePath,

            file,

            {

                cacheControl:
                    "3600",

                contentType:
                    file.type ||
                    "application/octet-stream",

                upsert:
                    true

            }

        );


    if (
        error
    ) {

        console.error(
            "SUPABASE — Replace failed:",
            error
        );


        throw error;

    }


    return data;

}


/* =========================================================
   DOWNLOAD CONTRACT DOCUMENT
========================================================= */

async function downloadContractDocument(

    storagePath

) {

    if (
        !storagePath
    ) {

        throw new Error(
            "No storage path specified."
        );

    }


    const bucket =
        getDocumentBucket();


    const {
        data,
        error
    } =
        await bucket.download(
            storagePath
        );


    if (
        error
    ) {

        console.error(
            "SUPABASE — Download failed:",
            error
        );


        throw error;

    }


    if (
        !data
    ) {

        throw new Error(
            "No document data received."
        );

    }


    return data;

}


/* =========================================================
   DELETE CONTRACT DOCUMENT
========================================================= */

async function deleteContractDocument(

    storagePath

) {

    if (
        !storagePath
    ) {

        throw new Error(
            "No storage path specified."
        );

    }


    const bucket =
        getDocumentBucket();


    const {
        data,
        error
    } =
        await bucket.remove([

            storagePath

        ]);


    if (
        error
    ) {

        console.error(
            "SUPABASE — Delete failed:",
            error
        );


        throw error;

    }


    return data;

}


/* =========================================================
   DELETE MULTIPLE DOCUMENTS
========================================================= */

async function deleteContractDocuments(

    storagePaths

) {

    if (
        !Array.isArray(
            storagePaths
        ) ||
        storagePaths.length === 0
    ) {

        return [];

    }


    const validPaths =
        storagePaths.filter(
            path =>
                typeof path ===
                "string" &&
                path.trim()
        );


    if (
        validPaths.length === 0
    ) {

        return [];

    }


    const bucket =
        getDocumentBucket();


    const {
        data,
        error
    } =
        await bucket.remove(
            validPaths
        );


    if (
        error
    ) {

        console.error(
            "SUPABASE — Multiple delete failed:",
            error
        );


        throw error;

    }


    return data;

}


/* =========================================================
   MOVE CONTRACT DOCUMENT
========================================================= */

async function moveContractDocument(

    oldPath,

    newPath

) {

    if (
        !oldPath ||
        !newPath
    ) {

        throw new Error(
            "Both document paths are required."
        );

    }


    const bucket =
        getDocumentBucket();


    const {
        data,
        error
    } =
        await bucket.move(

            oldPath,

            newPath

        );


    if (
        error
    ) {

        console.error(
            "SUPABASE — Move failed:",
            error
        );


        throw error;

    }


    return data;

}


/* =========================================================
   COPY CONTRACT DOCUMENT
========================================================= */

async function copyContractDocument(

    sourcePath,

    destinationPath

) {

    if (
        !sourcePath ||
        !destinationPath
    ) {

        throw new Error(
            "Both document paths are required."
        );

    }


    const bucket =
        getDocumentBucket();


    const {
        data,
        error
    } =
        await bucket.copy(

            sourcePath,

            destinationPath

        );


    if (
        error
    ) {

        console.error(
            "SUPABASE — Copy failed:",
            error
        );


        throw error;

    }


    return data;

}


/* =========================================================
   PUBLIC DOCUMENT URL
========================================================= */

/*
    The current bucket is PUBLIC.

    This function returns the public URL generated by
    Supabase Storage.

    Later, if we change the bucket to PRIVATE, this
    function can be replaced by the signed URL function
    below without changing Contract Management.
*/

function getContractDocumentPublicUrl(

    storagePath

) {

    if (
        !storagePath
    ) {

        return null;

    }


    const {
        data
    } =
        getDocumentBucket()
            .getPublicUrl(
                storagePath
            );


    return (
        data?.publicUrl ||
        null
    );

}


/* =========================================================
   SIGNED DOCUMENT URL
========================================================= */

/*
    Prepared for the future.

    This is the preferred approach if the bucket is
    changed from PUBLIC to PRIVATE.

    Expiration is expressed in seconds.

    Example:

        createSignedDocumentUrl(
            path,
            300
        );

    → URL valid for 5 minutes.
*/

async function createSignedDocumentUrl(

    storagePath,

    expiresIn =
        300

) {

    if (
        !storagePath
    ) {

        throw new Error(
            "No storage path specified."
        );

    }


    const safeExpiration =
        Math.max(
            60,
            Number(
                expiresIn
            ) || 300
        );


    const {
        data,
        error
    } =
        await getDocumentBucket()
            .createSignedUrl(

                storagePath,

                safeExpiration

            );


    if (
        error
    ) {

        console.error(
            "SUPABASE — Signed URL failed:",
            error
        );


        throw error;

    }


    return (
        data?.signedUrl ||
        null
    );

}


/* =========================================================
   LIST CONTRACT DOCUMENTS
========================================================= */

/*
    Returns files stored inside a contract folder.

    This is useful later for the Documents section
    inside Contract Management.
*/

async function listContractDocuments(

    contractId

) {

    const folder =
        buildContractFolderPath(
            contractId
        );


    const bucket =
        getDocumentBucket();


    const {
        data,
        error
    } =
        await bucket.list(

            folder,

            {

                limit:
                    100,

                offset:
                    0,

                sortBy:
                {

                    column:
                        "created_at",

                    order:
                        "desc"

                }

            }

        );


    if (
        error
    ) {

        console.error(
            "SUPABASE — List failed:",
            error
        );


        throw error;

    }


    return data || [];

}


/* =========================================================
   STORAGE HEALTH CHECK
========================================================= */

/*
    Does not upload, delete or modify anything.

    We simply verify that the configured bucket can
    be accessed.

    This function is diagnostic only.
*/

async function testSupabaseStorage() {

    try {

        const bucket =
            getDocumentBucket();


        const {
            data,
            error
        } =
            await bucket.list(

                "",

                {

                    limit:
                        1,

                    offset:
                        0

                }

            );


        if (
            error
        ) {

            console.warn(

                "SUPABASE — Storage check failed:",

                error

            );


            return false;

        }


        return Array.isArray(
            data
        );


    }
    catch(error) {

        console.error(

            "SUPABASE — Storage connection failed:",

            error

        );


        return false;

    }

}


/* =========================================================
   EXPORT
========================================================= */

export {

    /* Client */

    supabase,


    /* Configuration */

    SUPABASE_STORAGE,

    SUPABASE_STATUS,


    /* Access */

    getSupabase,

    getSupabaseStorage,

    getDocumentBucket,


    /* Paths */

    sanitizeFileName,

    sanitizeStorageSegment,

    buildContractDocumentPath,

    buildContractFolderPath,


    /* Validation */

    validateDocumentFile,


    /* Upload */

    uploadContractDocument,

    replaceContractDocument,


    /* Download */

    downloadContractDocument,


    /* Delete */

    deleteContractDocument,

    deleteContractDocuments,


    /* Organisation */

    moveContractDocument,

    copyContractDocument,


    /* URLs */

    getContractDocumentPublicUrl,

    createSignedDocumentUrl,


    /* Listing */

    listContractDocuments,


    /* Diagnostics */

    testSupabaseStorage

};


/* =========================================================
   OPTIONAL GLOBAL BRIDGE
========================================================= */

/*
    Expose the client and configuration for debugging
    and future compatibility.

    No application logic depends on this bridge.
*/

window.supabaseClient =
    supabase;


window.SUPABASE_STORAGE =
    SUPABASE_STORAGE;


window.SUPABASE_STATUS =
    SUPABASE_STATUS;

    