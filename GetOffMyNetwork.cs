/*  
 *  GetOffMyNetwork.cs - a Kerbal Space Program Plugin to control network traffic
 *  Copyright (C) 2014 Matthew Addison
 *
 *  This program is free software: you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation, either version 3 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

using Mono.Cecil;
using Mono.Cecil.Cil;
using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.IO;
using System.Linq;
using System.Reflection;
using System.Security.Cryptography;
using System.Text;
using UnityEngine;

namespace GetOffMyNetwork
{
    [KSPAddon(KSPAddon.Startup.EveryScene, false)]
    internal class GetOffMyNetwork : MonoBehaviour
    {
        // instance members for tracking the other assemblies and what they're allowed to do
        private static Dictionary<string, Assembly> _violators;
        private static Dictionary<string, bool> _permitted;
        private static Dictionary<string, Assembly> _assemblies;
        private static Dictionary<string, string> _hashes;
        private static Dictionary<string, ConfigNode> _nodes;

        // flags
        private static bool scanComplete;

        // config file related class members
        private static string configpath;
        private static ConfigNode confignode;

        // applauncher
        private static ApplicationLauncherButton GetOffMyNetworkButtonStock;
        private static string texturepath;

        // our Awake() function, moving some stuff from Start() to here to keep Start() leaner.
        // ksp instantiates us multiple times, so we static our variables to share logic
        void Awake()
        {
            if (scanComplete) return; // bail early if scanComplete set

            DebugPrint("Awake - scanComplete: {0}", scanComplete);

            // set up the dictionaries
            _assemblies = new Dictionary<string, Assembly>();
            _violators = new Dictionary<string, Assembly>();
            _permitted = new Dictionary<string, bool>();
            _hashes = new Dictionary<string, string>();
            _nodes = new Dictionary<string, ConfigNode>();

            // set up some variables
            string basepath = Path.GetDirectoryName(Uri.UnescapeDataString(new Uri(Assembly.GetExecutingAssembly().CodeBase).AbsolutePath)) + Path.DirectorySeparatorChar;
            configpath = basepath + "getoffmynetwork.cfg";
            texturepath = basepath + "getoffmynetwork";
            scanComplete = false;

            // try to load config
            confignode = ConfigNode.Load(configpath);
            if (confignode != null)
            {
                // DebugPrint("Parsing Config");
                foreach (ConfigNode node in confignode.nodes)
                {
                    // DebugPrint("Node: {0}", Uri.UnescapeDataString(node.getNodeValue<string>("codebase", string.Empty)));
                    _nodes.Add(Uri.UnescapeDataString(node.getNodeValue<string>("codebase", string.Empty)), node);
                }
            }
            else
                confignode = new ConfigNode();

            // subscribe to relevant game events
            GameEvents.onGUIApplicationLauncherReady.Add(OnGUIAppLauncherReady);

            DontDestroyOnLoad(this);
        }

        // our Start() function, where the (initial) magic happens.
        void Start()
        {
            bool newviolators = false;
            DebugPrint("Started - scanComplete: {0}", scanComplete);

            // scan for assemblies which may use network methods
            if (!scanComplete)
            {
                newviolators = scanForViolators();
                scanComplete = true;
            }

            // I'm assuming after we pop the dialog KSP continues to process in the background, so we need to disable now
            // note: tried implementing a thread lock here but ksp deadlocks, guess blocking Start() blocks the main dispatch loop
            disableViolators();

            // if we had some new assemblies found which use network functions, prompt to whitelist them
            if (newviolators) promptForOptIn();
        }

        // display our MultiOptionDialog to let the user opt-in
        private void promptForOptIn()
        {
            // prompt about violators, give user opportunity to opt-in
            var mod = new MultiOptionDialog(
                "New plugins have been detected which might access the network. Please opt-in as you see fit. Please be aware you will need to restart KSP for these changes to take effect.",
                new Callback(this.listViolators),
                "GetOffMyNetwork", HighLogic.Skin,
                new DialogOption("OK", new Callback(this.saveViolators), true)
                );
            mod.dialogRect = new Rect((float)(Screen.width / 2 - 400), (float)(Screen.height / 2 - 50), 800f, 100f);
            PopupDialog.SpawnPopupDialog(mod, true, HighLogic.Skin);
        }

        // used in Start() to scan for assemblies containing references which might access the network
        private bool scanForViolators()
        {
            bool newviolators = false;

            // step through all the assemblies, and check for violations
            foreach (var assembly in getAllAssembliesWithMonobehaviors())
            {
                bool matched = false;
                _assemblies.Add(assembly.CodeBase, assembly);
                _hashes.Add(assembly.CodeBase, getAssemblyHash(new Uri(assembly.CodeBase)));

                // check for confignode
                if (_nodes.Keys.Contains(assembly.CodeBase))
                {
                    // DebugPrint("Found ConfigNode For {0}", assembly.CodeBase);
                    var node = _nodes[assembly.CodeBase];
                    bool permitted = node.getNodeValue<bool>("permitted", false);
                    bool violator = node.getNodeValue<bool>("violator", false);
                    string hash = node.getNodeValue<string>("hash", string.Empty);
                    if (hash == _hashes[assembly.CodeBase])
                    {
                        matched = true;
                        // DebugPrint("Setting matched = true for {0}", assembly.CodeBase);
                        if (violator)
                        {
                            _violators.Add(assembly.CodeBase, assembly);
                            _permitted.Add(assembly.CodeBase, false);
                        }
                        if (permitted)
                            _permitted[assembly.CodeBase] = true;
                    }
                }
                if (!matched)
                {
                    if (checkAssemblyForViolations(assembly))
                    {
                        DebugPrint("Module {0} contains network functions!", assembly.ToString());
                        _violators.Add(assembly.CodeBase, assembly);
                        _permitted.Add(assembly.CodeBase, false);
                        newviolators = true;
                    }
                }
            }

            return newviolators;
        }

        // callback used by MultiOptionDialog to add toggle boxes for all current members of the violators list
        public void listViolators()
        {
            // this callback is used in MultiOptionDialog calls to display a list of toggle/check boxes for mods we haven't whitelisted
            foreach (var key in _violators.Keys)
            {
                Assembly violator = _violators[key];
                List<string> words = new List<string>(violator.CodeBase.Split('/'));
                var idx = words.FindLastIndex((string word) => { return (word.ToLower() == "gamedata"); });
                string localpath = "";
                if (idx != -1) { 
                    localpath = words.GetRange(idx, words.Count - idx).Aggregate((i, j) => i + "/" + j); 
                } else { 
                    localpath = violator.CodeBase; 
                }
                // DebugPrint("Adding {0} to dialog", violator);
                _permitted[violator.CodeBase] = GUILayout.Toggle(_permitted[violator.CodeBase], String.Format("Enable {0} ({1})?", violator.GetName().Name, localpath));
            }
        }

        // enable/disable monobehaviours based on violator status, and serialize our config. run after config dialog is closed
        private void saveViolators()
        {
            foreach (string key in _assemblies.Keys)
            {
                ConfigNode node = getNewNode(key, _hashes[key], _violators.Keys.Contains(key), (_permitted.Keys.Contains(key) && _permitted[key]));
                // Commenting this out for now, it was the code to re-enable disabled monobehaviours in blacklisted modules that were now whitelisted
                // but Greys' comment http://forum.kerbalspaceprogram.com/threads/88963#post1320181 makes me think this could end up with some wonky corner cases
                // if (_permitted.Keys.Contains(key) && _permitted[key])
                // {
                //     setAssemblyMonobehaviorInstanceEnabled(_violators[key], true);
                // }
                // DebugPrint("ConfigNode for {0}: {1}", key, node);
                if (_nodes.Keys.Contains(key))
                {
                    _nodes[key] = node;
                }
                else
                {
                    _nodes.Add(key, node);
                }
            }
            confignode.ClearNodes();
            foreach (var key in _nodes.Keys)
            {
                confignode.AddNode(_nodes[key]);
            }
            // DebugPrint("Final ConfigNode: {0}", confignode);
            confignode.Save(configpath);
        }

        // return a new ConfigNode based on a codebase (URI), hash, and violator/permitted bits
        private ConfigNode getNewNode(string codebase, string hash, bool violator, bool permitted)
        {
            var sha2 = SHA256.Create();
            sha2.ComputeHash(getBytes(codebase));
            var newnode = new ConfigNode(BitConverter.ToString(sha2.Hash).Replace("-", string.Empty)); // confignode is base64 encoded sha2 hash of file path
            newnode.AddValue("codebase", Uri.EscapeUriString(codebase).Replace("/", Uri.HexEscape('/')));
            newnode.AddValue("hash", hash);
            newnode.AddValue("violator", violator);
            newnode.AddValue("permitted", permitted);
            return newnode;
        }

        private static byte[] getBytes(string str)
        {
            byte[] bytes = new byte[str.Length * sizeof(char)];
            System.Buffer.BlockCopy(str.ToCharArray(), 0, bytes, 0, bytes.Length);
            return bytes;
        }

        // disables monobehaviors based on assemblies in _violators, honors _permitted
        private void disableViolators()
        {
            foreach (var key in _violators.Keys)
            {
                if (_permitted.Keys.Contains(key) && _permitted[key] == true) continue;
                setAssemblyMonobehaviorInstanceEnabled(_violators[key]);
            }
        }

        // load the types, load the methods on the types, inspect them for network functions, return true if found
        private static bool checkAssemblyForViolations(Assembly assembly)
        {
            if (!assembly.CodeBase.Contains("GameData")) return false; // only process assemblies inside GameData\, i.e. plugins following the rules.
            var module = ModuleDefinition.ReadModule(new Uri(assembly.CodeBase).LocalPath);
            foreach (var type in module.GetTypes())
            {
                foreach (var method in type.Methods)
                {
                    // skip null methods, and methods declared on parent objects (already inspected, or part of base ksp)
                    if (method == null || method.DeclaringType != type || method.Body == null) continue;
                    foreach (var instruction in method.Body.Instructions)
                    {
                        if ((instruction.OpCode == OpCodes.Call || instruction.OpCode == OpCodes.Callvirt || instruction.OpCode == OpCodes.Newobj) && instruction.Operand != null)
                        {
                            MethodReference methodCall = instruction.Operand as MethodReference;
                            if (methodCall != null && methodCall.FullName != null)
                            {
                                if (methodCall.FullName.Contains("System.Net"))          return true;
                                if (methodCall.FullName.Contains("UnityEngine.Network")) return true;
                                if (methodCall.FullName.Contains("UnityEngine.WWW"))     return true;
                            }
                        }
                    }
                }
            }
            return false; // fall through, no violation
        }

        // enables/disables instantiated monobehaviours in an assembly
        private static void setAssemblyMonobehaviorInstanceEnabled(Assembly assembly, Boolean enabled = false)
        {
            foreach (var type in getAllAssemblyMonobehaviours(assembly))
            {
                DebugPrint("Monobehaviour: {0}, Setting enabled = {1}", type, (enabled) ? "true" : "false");
                foreach (MonoBehaviour instance in UnityEngine.GameObject.FindObjectsOfType(type))
                {
                    if (instance.enabled != enabled)
                    {
                        DebugPrint("Found {1} Monobehaviour Instance: {0}", instance, (enabled) ? "disabled" : "enabled");
                        instance.enabled = enabled;
                        if (!enabled)
                        {
                            // stop all pending invocations and coroutines
                            instance.CancelInvoke();
                            instance.StopAllCoroutines();
                            instance.Invoke("OnDestroy", 0.0f); // run the OnDestroy to trigger cleanup of anything from Awake()
                        }
                    }
                }
            }
        }

        // returns an IEnumberable of all assemblies which contain classes deriving from UnityEngine.Monobehaviour
        private static IEnumerable<Assembly> getAllAssembliesWithMonobehaviors()
        {
            List<Assembly> assemblies = new List<Assembly>();
            foreach (var assembly in AppDomain.CurrentDomain.GetAssemblies())
            {
                try
                {
                    foreach (var type in assembly.GetTypes())
                    {
                        if (type.BaseType != typeof(MonoBehaviour)) continue;
                        assemblies.Add(assembly);
                        break;
                    }
                }
                catch
                {
                    DebugPrint("Exception in getAllAssembliesWithMonobehaviors");
                }
            }
            return assemblies;
        }

        // returns an IEnumerable of all Monobehaviour derived classes in a given Assembly
        private static IEnumerable<Type> getAllAssemblyMonobehaviours(Assembly assembly)
        {
            List<Type> types = new List<Type>();
            foreach (var type in assembly.GetTypes())
            {
                try
                {
                    if (type.BaseType != typeof(MonoBehaviour)) continue;
                    types.Add(type);
                }
                catch
                {
                    DebugPrint("Exception in getAllAssemblyMonobehaviours");
                }
            }
            return types;
        }

        // returns sha256 hash in hexidecimal format for a given Uri path, we use Uris instead of plain strings to workaround temp directory issues under test frameworks
        // which we aren't currently using, but you never know
        private static string getAssemblyHash(Uri path)
        {
            if (!path.IsFile) return ""; // should never hit this, but safety first
            var stream = File.Open(path.LocalPath, FileMode.Open, FileAccess.Read);
            var sha2 = SHA256.Create();
            sha2.ComputeHash(stream);
            stream.Close();
            return BitConverter.ToString(sha2.Hash).Replace("-", string.Empty);
        }

        // applauncher - clicked
        public void OnAppLaunchToggle()
        {

        }

        // applauncher - OnGUIAppLauncherReady
        public void OnGUIAppLauncherReady()
        {
            if (ApplicationLauncher.Ready && HighLogic.LoadedSceneIsFlight && GetOffMyNetworkButtonStock == null)
            {
                GetOffMyNetworkButtonStock = ApplicationLauncher.Instance.AddModApplication(
                    OnAppLaunchToggle,
                    OnAppLaunchToggle,
                    null,
                    null,
                    null,
                    null,
                    ApplicationLauncher.AppScenes.SPACECENTER,
                    (Texture)GameDatabase.Instance.GetTexture("000_StillBetterThanSpyware/getoffmynetwork", false)); // TODO: changeme to final distribution directory
                GameEvents.onGUIApplicationLauncherReady.Remove(OnGUIAppLauncherReady);
                GameEvents.onGUIApplicationLauncherDestroyed.Add(OnGUIAppLauncherDestroyed);
            }
        }

        // applauncher - OnGUIAppLauncherDestroyed
        public void OnGUIAppLauncherDestroyed()
        {
            if (GetOffMyNetworkButtonStock != null)
            {
                ApplicationLauncher.Instance.RemoveModApplication(GetOffMyNetworkButtonStock);
                GetOffMyNetworkButtonStock = null;
            }
            GameEvents.onGUIApplicationLauncherDestroyed.Remove(OnGUIAppLauncherDestroyed);        
            GameEvents.onGUIApplicationLauncherReady.Add(OnGUIAppLauncherReady);
        }

        // wrapper for Debug.Log to always use String.Format and add our prefix
        private static void DebugPrint(string format, params object[] list)
        {
            Debug.Log(String.Format("[GetOffMyNetwork] " + format, list));
        }
    }

    // internal extensions for other classes
    internal static class Extensions
    {
        // generic getNodeValue method to get a properly typed configNode value
        // from blizzy78 ksp_toolbar
        internal static T getNodeValue<T>(this ConfigNode configNode, string name, T defaultValue)
        {
            if (configNode.HasValue(name))
            {
                Type type = typeof(T);
                TypeConverter converter = TypeDescriptor.GetConverter(type);
                string value = configNode.GetValue(name);
                return (T)converter.ConvertFromInvariantString(value);
            }
            else
            {
                return defaultValue;
            }
        }
    }
}
