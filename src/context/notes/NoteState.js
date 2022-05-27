import NoteContext from "./NoteContext";
import { useState } from "react";

const NoteState = (props) => {
    const host = "http://localhost:5000";
    const notesInitial = []



    const [notes, setNotes] = useState(notesInitial)


    //Get all Notes
    const getNotes = async (title, description, tag) => {
        //API Call
        // eslint-disable-next-line
        const response = await fetch(`${host}/api/notes/fetchallnotes`, {
            method: 'GET',
            headers: {
                'Content-Type': 'application/json',
                'auth-token': localStorage.getItem('auth-token') 
            },
        });
        const json = await response.json();
        setNotes(json);
    }
    // Add a Note
    const addNote = async (title, description, tag) => {
        //API Call
        // eslint-disable-next-line
        const response = await fetch(`${host}/api/notes/addnote`, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                'auth-token': localStorage.getItem('auth-token') 
            },
            body: JSON.stringify({ title, description, tag })
        });

        //Adding a new Note
        const note = await response.json();
         setNotes(notes.concat(note));//  This is the original revert it
        // setNotes(Object.keys(notes).concat(note)); // del later
    }
    // Delete a Note
    const deleteNote = async (id) => {
        //API Call
        // eslint-disable-next-line
        const response = await fetch(`${host}/api/notes/deletenote/${id}`, {
            method: 'DELETE',
            headers: {
                'Content-Type': 'application/json',
                'auth-token': localStorage.getItem('auth-token')  
            },
        });
        // const json = response.json();
        const newNotes = notes.filter((note) => { return note._id !== id });
        setNotes(newNotes);
    }
    // Edit a Note
    const editNote = async (id, title, description, tag) => {
        //API Call
        // eslint-disable-next-line
        const response = await fetch(`${host}/api/notes/updatenote/${id}`, {
            method: 'PUT',
            headers: {
                'Content-Type': 'application/json',
                'auth-token': localStorage.getItem('auth-token')
               
            },
            body: JSON.stringify({ title, description, tag })
        });
        //const json = response.json();

        //Logic to edit in client
        let newNotes = JSON.parse(JSON.stringify(notes));
        for (let index = 0; index < newNotes.length; index++) {
            const element = newNotes[index];
            if (element._id === id) {
                newNotes[index].title = title;
                newNotes[index].description = description;
                newNotes[index].tag = tag;
                break;
            }
        }
        setNotes(newNotes);
    }
    return (
        <NoteContext.Provider value={{ notes, addNote, deleteNote, editNote, getNotes }}>
            {props.children}
        </NoteContext.Provider>
    )
}
export default NoteState;