/* =========================================================
   RYANAIR FINANCIAL DASHBOARD
   FIREBASE CORE
   =========================================================

   RESPONSIBILITIES
   ----------------
   Firebase is the CORE backend of this application.

   Firebase Realtime Database
       → Users
       → Roles
       → Permissions
       → Dashboard data
       → Contracts metadata
       → Audit logs
       → Application state

   Firebase Authentication
       → Reserved for future authentication integration

   Firebase Storage
       → Reserved for future Firebase-hosted files
       → Contract documents will NOT use this by default

   Supabase
       → Physical contract/document storage
       → Added separately in the application when needed

   IMPORTANT
   ----------
   This file creates ONE Firebase App only.

   Other modules must reuse this same app/services.

========================================================= */


/* =========================================================
   FIREBASE SDK
========================================================= */

import {
    initializeApp,
    getApps,
    getApp
} from
    "https://www.gstatic.com/firebasejs/10.11.0/firebase-app.js";

import {
    getAuth
} from
    "https://www.gstatic.com/firebasejs/10.11.0/firebase-auth.js";


import {
    getDatabase,
    ref,
    get,
    set,
    update,
    remove,
    push,
    onValue,
    onChildAdded,
    onChildChanged,
    onChildRemoved
} from
    "https://www.gstatic.com/firebasejs/10.11.0/firebase-database.js";


import {
    getStorage
} from
    "https://www.gstatic.com/firebasejs/10.11.0/firebase-storage.js";


/* =========================================================
   FIREBASE CONFIGURATION
========================================================= */

const firebaseConfig = {

    apiKey:
        "AIzaSyDPek02vtDyudrxOpK6BA8mdJXWguZlABc",

    authDomain:
        "opo-financial-dashboard.firebaseapp.com",

    databaseURL:
        "https://opo-financial-dashboard-default-rtdb.europe-west1.firebasedatabase.app",

    projectId:
        "opo-financial-dashboard",

    storageBucket:
        "opo-financial-dashboard.firebasestorage.app",

    messagingSenderId:
        "383795290832",

    appId:
        "1:383795290832:web:1b0bb388601e5807dc74d5",

};


/* =========================================================
   FIREBASE APP
========================================================= */

/*
   IMPORTANT:

   If another Firebase App has already been created,
   reuse it instead of creating another instance.

   This prevents the same problem we explicitly avoid
   in the Engineering Dashboard File Store.
*/

const app =
    getApps().length
        ? getApp()
        : initializeApp(
            firebaseConfig
        );


/* =========================================================
   FIREBASE SERVICES
========================================================= */


const auth =
    getAuth(
        app
    );


const database =
    getDatabase(
        app
    );


const storage =
    getStorage(
        app
    );


/* =========================================================
   DATABASE ROOTS
========================================================= */

/*
   These paths intentionally remain centralised.

   Future modules should NOT hard-code database roots
   everywhere.

   Example:

       databaseRef(
           DATABASE_PATHS.USERS + "/" + username
       )

*/

const DATABASE_PATHS = {

    USERS:
        "users",

    LOGS:
        "logs",

    SYSTEM:
        "system",

    DASHBOARD:
        "dashboardData",

    CONTRACTS:
        "dashboardData/contracts",

    CONTRACT_DOCUMENTS:
        "dashboardData/contracts/documents",

    SETTINGS:
        "dashboardData/settings"

};


/* =========================================================
   SESSION STORAGE
========================================================= */

const SESSION_STORAGE_KEY =
    "RYANAIR_FINANCIAL_SESSION";


/* =========================================================
   APPLICATION CONSTANTS
========================================================= */

const APP_CONFIG = {

    name:
        "Ryanair Financial Dashboard",

    version:
        "1.0.0",

    firebaseProject:
        "opo-financial-dashboard",

    databaseRegion:
        "europe-west1",

    documentStorage:
        "supabase"

};

/* =========================================================
   APPLICATION DATABASE REFERENCES
========================================================= */

/*
   Centralised database references.

   IMPORTANT:
   Other modules should use these helpers instead of
   manually rebuilding Firebase paths.

   Structure:

   users/
       username/
           profile/
           credentials/
           permissions/
           metadata/

   system/
       security/

   logs/
*/


/* =========================================================
   USER ROOT
========================================================= */

function userRef(
    username
){

    const cleanUsername =
        String(
            username || ""
        )
            .trim()
            .toLowerCase();


    if(
        !cleanUsername
    ){

        throw new Error(
            "INVALID_USERNAME_REFERENCE"
        );

    }


    return firebaseRef(

        `${DATABASE_PATHS.USERS}/${cleanUsername}`

    );

}


/* =========================================================
   USER PROFILE
========================================================= */

function userProfileRef(
    username
){

    return firebaseRef(

        `${DATABASE_PATHS.USERS}/${String(
            username
        )
            .trim()
            .toLowerCase()}/profile`

    );

}


/* =========================================================
   USER CREDENTIALS
========================================================= */

function userCredentialsRef(
    username
){

    return firebaseRef(

        `${DATABASE_PATHS.USERS}/${String(
            username
        )
            .trim()
            .toLowerCase()}/credentials`

    );

}


/* =========================================================
   USER PERMISSIONS
========================================================= */

function userPermissionsRef(
    username
){

    return firebaseRef(

        `${DATABASE_PATHS.USERS}/${String(
            username
        )
            .trim()
            .toLowerCase()}/permissions`

    );

}


/* =========================================================
   USER METADATA
========================================================= */

function userMetadataRef(
    username
){

    return firebaseRef(

        `${DATABASE_PATHS.USERS}/${String(
            username
        )
            .trim()
            .toLowerCase()}/metadata`

    );

}


/* =========================================================
   SECURITY
========================================================= */

function securityRef(){

    return firebaseRef(

        `${DATABASE_PATHS.SYSTEM}/security`

    );

}


/* =========================================================
   SYSTEM SETTINGS
========================================================= */

function settingsRef(){

    return firebaseRef(

        DATABASE_PATHS.SETTINGS

    );

}


/* =========================================================
   SYSTEM METADATA
========================================================= */

function systemMetadataRef(){

    return firebaseRef(

        `${DATABASE_PATHS.SYSTEM}/metadata`

    );

}


/* =========================================================
   LOGS
========================================================= */

function logsRef(){

    return firebaseRef(

        DATABASE_PATHS.LOGS

    );

}


/* =========================================================
   CONTRACTS
========================================================= */

function contractsRef(){

    return firebaseRef(

        DATABASE_PATHS.CONTRACTS

    );

}


/* =========================================================
   CONTRACT
========================================================= */

function contractRef(
    contractId
){

    const id =
        String(
            contractId || ""
        ).trim();


    if(
        !id
    ){

        throw new Error(
            "INVALID_CONTRACT_ID"
        );

    }


    return firebaseRef(

        `${DATABASE_PATHS.CONTRACTS}/${id}`

    );

}


/* =========================================================
   CONTRACT DOCUMENTS
========================================================= */

function contractDocumentsRef(){

    return firebaseRef(

        DATABASE_PATHS.CONTRACT_DOCUMENTS

    );

}


/* =========================================================
   CONTRACT DOCUMENT
========================================================= */

function contractDocumentRef(
    contractId,
    documentId
){

    const cleanContractId =
        String(
            contractId || ""
        ).trim();


    const cleanDocumentId =
        String(
            documentId || ""
        ).trim();


    if(
        !cleanContractId ||
        !cleanDocumentId
    ){

        throw new Error(
            "INVALID_CONTRACT_DOCUMENT_REFERENCE"
        );

    }


    return firebaseRef(

        `${DATABASE_PATHS.CONTRACT_DOCUMENTS}/${cleanContractId}/${cleanDocumentId}`

    );

}

/* =========================================================
   DATABASE HELPERS
========================================================= */

/*
   Create a Firebase Database reference.

   Example:

       firebaseRef(
           "users/john"
       )

*/

function firebaseRef(
    path
) {

    return ref(
        database,
        path
    );

}


/* =========================================================
   GET
========================================================= */

async function firebaseGet(
    reference
) {

    return await get(
        reference
    );

}


/* =========================================================
   SET
========================================================= */

async function firebaseSet(
    reference,
    value
) {

    return await set(
        reference,
        value
    );

}


/* =========================================================
   UPDATE
========================================================= */

async function firebaseUpdate(
    reference,
    value
) {

    return await update(
        reference,
        value
    );

}


/* =========================================================
   REMOVE
========================================================= */

async function firebaseRemove(
    reference
) {

    return await remove(
        reference
    );

}


/* =========================================================
   PUSH
========================================================= */

function firebasePush(
    reference
) {

    return push(
        reference
    );

}


/* =========================================================
   REALTIME LISTENER
========================================================= */

function firebaseListen(
    reference,
    callback
) {

    return onValue(
        reference,
        callback
    );

}


/* =========================================================
   CHILD LISTENERS
========================================================= */

function firebaseOnChildAdded(
    reference,
    callback
) {

    return onChildAdded(
        reference,
        callback
    );

}


function firebaseOnChildChanged(
    reference,
    callback
) {

    return onChildChanged(
        reference,
        callback
    );

}


function firebaseOnChildRemoved(
    reference,
    callback
) {

    return onChildRemoved(
        reference,
        callback
    );

}


/* =========================================================
   STORAGE
========================================================= */

/*
   Firebase Storage is initialised and available.

   Contract documents should use Supabase Storage
   according to the Engineering Dashboard architecture.

   Firebase Storage remains available for future needs.
*/

function getFirebaseStorage() {

    return storage;

}


/* =========================================================
   AUTH
========================================================= */

function getFirebaseAuth() {

    return auth;

}


/* =========================================================
   DATABASE
========================================================= */

function getFirebaseDatabase() {

    return database;

}


/* =========================================================
   APP
========================================================= */

function getFirebaseApp() {

    return app;

}


/* =========================================================
   SESSION HELPERS
========================================================= */

function saveLocalSession(
    session
) {

    if(
        !session
    ) {

        return;

    }


    localStorage.setItem(

        SESSION_STORAGE_KEY,

        JSON.stringify(
            session
        )

    );

}


function getLocalSession() {

    const stored =
        localStorage.getItem(
            SESSION_STORAGE_KEY
        );


    if(
        !stored
    ) {

        return null;

    }


    try {

        return JSON.parse(
            stored
        );

    }
    catch(error) {

        console.warn(
            "Invalid stored session."
        );

        localStorage.removeItem(
            SESSION_STORAGE_KEY
        );

        return null;

    }

}


function clearLocalSession() {

    localStorage.removeItem(
        SESSION_STORAGE_KEY
    );

}


/* =========================================================
   CONNECTION TEST
========================================================= */

async function testFirebaseConnection() {

    try {

        const reference =
            firebaseRef(
                DATABASE_PATHS.SYSTEM
            );


        await get(
            reference
        );


        return true;

    }
    catch(error) {

        console.error(
            "Firebase connection test failed:",
            error
        );


        return false;

    }

}


/* =========================================================
   GLOBAL FIREBASE STATUS
========================================================= */

const FIREBASE_STATUS = {

    initialized:
        true,

    project:
        APP_CONFIG.firebaseProject,

    database:
        true,

    authentication:
        true,

    storage:
        true

};

/* =========================================================
   EXPORT
========================================================= */

export {

    /* Firebase core */

    app,

    auth,

    database,

    storage,


    /* Database */

    DATABASE_PATHS,


    /* Application */

    APP_CONFIG,

    FIREBASE_STATUS,


    /* Database helpers */

    firebaseRef,

    firebaseGet,

    firebaseSet,

    firebaseUpdate,

    firebaseRemove,

    firebasePush,


    /* Application references */

    userRef,

    userProfileRef,

    userCredentialsRef,

    userPermissionsRef,

    userMetadataRef,

    securityRef,

    settingsRef,

    systemMetadataRef,

    logsRef,

    contractsRef,

    contractRef,

    contractDocumentsRef,

    contractDocumentRef,


    /* Existing listeners */

    firebaseListen,

    firebaseOnChildAdded,

    firebaseOnChildChanged,

    firebaseOnChildRemoved,


    /* Services */

    getFirebaseApp,

    getFirebaseAuth,

    getFirebaseDatabase,

    getFirebaseStorage,


    /* Sessions */

    SESSION_STORAGE_KEY,

    saveLocalSession,

    getLocalSession,

    clearLocalSession,


    /* Diagnostics */

    testFirebaseConnection

};


/* =========================================================
   OPTIONAL GLOBAL BRIDGE
========================================================= */

/*
   The Engineering Dashboard currently uses functions such as:

       firebaseGet()
       firebaseSet()
       firebaseUpdate()
       firebaseRemove()
       firebaseRef()
       firebasePush()

   We expose the same style globally so future modules
   can use the same architecture without creating
   another Firebase instance.
*/

window.firebaseRef =
    firebaseRef;


window.firebaseGet =
    firebaseGet;


window.firebaseSet =
    firebaseSet;


window.firebaseUpdate =
    firebaseUpdate;


window.firebaseRemove =
    firebaseRemove;


window.firebasePush =
    firebasePush;


window.firebaseListen =
    firebaseListen;


window.firebaseOnChildAdded =
    firebaseOnChildAdded;


window.firebaseOnChildChanged =
    firebaseOnChildChanged;


window.firebaseOnChildRemoved =
    firebaseOnChildRemoved;


window.firebaseDatabase =
    database;


window.firebaseAuth =
    auth;


window.firebaseStorage =
    storage;


window.firebaseApp =
    app;


window.FIREBASE_STATUS =
    FIREBASE_STATUS;


window.DATABASE_PATHS =
    DATABASE_PATHS;onkeydown