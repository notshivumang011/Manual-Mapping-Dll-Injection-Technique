# 🚀 Manual Mapping DLL Injection (x64)

Welcome to **Manual Mapping DLL Injection**, a project that demonstrates how to inject DLLs into target processes by **completely bypassing the Windows loader (`LoadLibrary`)**.  
This is a **64-bit Manual Mapping Injector** built in **C++**, designed for research and educational purposes to understand the internal workings of the Windows Portable Executable (PE) format and advanced DLL injection techniques.

---

## 📌 What is Manual Mapping?

Normally, DLL injection relies on `LoadLibrary` to load a DLL into a remote process. However, this leaves traces and is easily detected by security systems.  

**Manual Mapping** avoids this by:  
1. **Reading the DLL file** into memory in the injector.  
2. **Parsing PE headers** (DOS Header, NT Headers, Section Headers).  
3. **Allocating memory** inside the target process.  
4. **Copying sections** into the remote memory.  
5. **Applying relocations** if the base address differs.  
6. **Resolving imports** by loading required functions manually.  
7. **Executing the entry point (DllMain / exported function)** using a **newly created remote thread** — without calling `LoadLibrary`.

This makes the technique more **stealthy, powerful, and closer to how the Windows loader works internally**.

---

## ✨ Key Features

- 🧩 **Pure Manual Mapping** (bypasses `LoadLibrary`)  
- 🔄 Handles **relocations** & **import resolution** like Windows loader  
- 🛠️ Executes DLL entry point via **`CreateRemoteThread`**  
- 💻 Built for **x64 processes** with modern C++  
- 🧠 Great for **understanding Windows PE internals**  
- 🔒 More stealthy compared to classic injection methods  

---

## 📂 Project Structure

![Project Structure](https://raw.githubusercontent.com/notshivumang011/Manual-Mapping-Dll-Injection-Technique/refs/heads/main/manual%20mpp.png))
