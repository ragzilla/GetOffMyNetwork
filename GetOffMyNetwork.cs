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
using System.Linq;
using System.Reflection;
using System.Text;
using UnityEngine;

namespace GetOffMyNetwork
{
    [KSPAddon(KSPAddon.Startup.Instantly, true)]
    internal class GetOffMyNetwork : MonoBehaviour
    {
        private List<Assembly> _violators;

        void Start()
        {
            Debug.Log("[GetOffMyNetwork] Started");

            _violators = new List<Assembly>();

            // step through all the assemblies, and check for violations
            foreach (var assembly in getAllAssembliesWithMonobehaviors())
            {
                if (checkAssemblyForViolations(assembly))
                {
                    Debug.Log(String.Format("[GetOffMyNetwork] Module {0} contains network functions!", assembly.ToString()));
                    _violators.Add(assembly);
                }
            }
            disableViolators();
        }

        private void disableViolators()
        {
            foreach (var assembly in _violators) disableAssemblyMonobehaviorInstances(assembly);
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

        private static void disableAssemblyMonobehaviorInstances(Assembly assembly)
        {
            foreach (var type in getAllAssemblyMonobehaviours(assembly))
            {
                Debug.Log(String.Format("[GetOffMyNetwork] Disabling Monobehaviour: {0}", type));
                //MonoBehaviour monotype = (MonoBehaviour)type;
                //monotype.enabled = false;
                //type.
                foreach (MonoBehaviour instance in UnityEngine.GameObject.FindObjectsOfType(type))
                {
                    Debug.Log(String.Format("[GetOffMyNetwork] Found Monobehaviour Instance: {0}", instance));
                    instance.enabled = false;
                }
            }
        }

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
                    Debug.Log("[GetOffMyNetwork] Exception in getAllAssembliesWithMonobehaviors");
                }
            }
            return assemblies;
        }

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
                    Debug.Log("[GetOffMyNetwork] Exception in getAllAssemblyMonobehaviours");
                }
            }
            return types;
        }
    }
}
