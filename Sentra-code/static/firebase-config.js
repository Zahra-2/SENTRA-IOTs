// Firebase configuration using ESM (Browser modules)
import { initializeApp } from 'https://www.gstatic.com/firebasejs/11.4.0/firebase-app.js';
import {
	getAuth,
	signInWithEmailAndPassword,
	createUserWithEmailAndPassword,
	signOut,
	onAuthStateChanged,
	GoogleAuthProvider,
	TwitterAuthProvider,
	signInWithPopup,
} from 'https://www.gstatic.com/firebasejs/11.4.0/firebase-auth.js';
import {
	getFirestore,
	collection,
	doc,
	setDoc,
	getDoc,
	updateDoc,
	serverTimestamp,
} from 'https://www.gstatic.com/firebasejs/11.4.0/firebase-firestore.js';

// Your web app's Firebase configuration
// Replace with your actual Firebase project configuration
const firebaseConfig = {
	apiKey: 'AIzaSyC3KHLcXm5ecbPGlz054us-tB-l_bb0j4M',
	authDomain: 'sentra-iot.firebaseapp.com',
	projectId: 'sentra-iot',
	storageBucket: 'sentra-iot.firebasestorage.app',
	messagingSenderId: '261305322748',
	appId: '1:261305322748:web:f10db4b512c60f14375b79',
	measurementId: 'G-D0ZSWN0G0P',
};

// Initialize Firebase
const app = initializeApp(firebaseConfig);
const auth = getAuth(app);
const db = getFirestore(app);

// Export functions and instances that will be used in different pages
export {
	app,
	auth,
	db,
	signInWithEmailAndPassword,
	createUserWithEmailAndPassword,
	signOut,
	onAuthStateChanged,
	GoogleAuthProvider,
	TwitterAuthProvider,
	signInWithPopup,
	collection,
	doc,
	setDoc,
	getDoc,
	updateDoc,
	serverTimestamp,
};
