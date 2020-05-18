environment：
    
    v8 commit id: 568979f4d891bafec875fab20f608ff9392f4f29

exp1.js:

    fake ArrayBuffer/map to get arbitrary read/write

exp2.js:

    make obj size shrink to overwirte JSArray's length filed, then, get an OOB array.