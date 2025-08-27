from fastapi import FastAPI, HTTPException
from typing import Any

from mcp.server.fastmcp import FastMCP
from mcp.server.sse import SseServerTransport
from starlette.applications import Starlette
from starlette.routing import Route, Mount

import os
import json
import logging
import ssl
import argparse
from dataclasses import dataclass
from typing import Optional, Dict, Any

# pyVmomi VMware API imports
from pyVim import connect
from pyVmomi import vim, vmodl

# Configuration data class for storing configuration options
@dataclass
class Config:
    vcenter_host: str
    vcenter_user: str
    vcenter_password: str
    datacenter: Optional[str] = None   # Datacenter name (optional)
    cluster: Optional[str] = None      # Cluster name (optional)
    datastore: Optional[str] = None    # Datastore name (optional)
    network: Optional[str] = None      # Virtual network name (optional)
    insecure: bool = False             # Whether to skip SSL certificate verification (default: False)
    api_key: Optional[str] = None      # API access key for authentication
    log_file: Optional[str] = None     # Log file path (if not specified, output to console)
    log_level: str = "INFO"            # Log level


# VMware management class, encapsulating pyVmomi operations for vSphere
class VMwareManager:
    def __init__(self, config: Config):
        self.config = config
        self.si = None               # Service instance (ServiceInstance)
        self.content = None          # vSphere content root
        self.datacenter_obj = None
        self.resource_pool = None
        self.datastore_obj = None
        self.network_obj = None
        self.authenticated = False   # Authentication flag for API key verification
        self._connect_vcenter()

    def _connect_vcenter(self):
        """Connect to vCenter/ESXi and retrieve main resource object references."""
        try:
            if self.config.insecure:
                # Connection method without SSL certificate verification
                context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
                context.check_hostname = False  # Disable hostname checking
                context.verify_mode = ssl.CERT_NONE
                self.si = connect.SmartConnect(
                    host=self.config.vcenter_host,
                    user=self.config.vcenter_user,
                    pwd=self.config.vcenter_password,
                    sslContext=context)
            else:
                # Standard SSL verification connection
                self.si = connect.SmartConnect(
                    host=self.config.vcenter_host,
                    user=self.config.vcenter_user,
                    pwd=self.config.vcenter_password)
        except Exception as e:
            logging.error(f"Failed to connect to vCenter/ESXi: {e}")
            raise
        # Retrieve content root object
        self.content = self.si.RetrieveContent()
        logging.info("Successfully connected to VMware vCenter/ESXi API")

        # Retrieve target datacenter object
        if self.config.datacenter:
            # Find specified datacenter by name
            self.datacenter_obj = next((dc for dc in self.content.rootFolder.childEntity
                                        if isinstance(dc, vim.Datacenter) and dc.name == self.config.datacenter), None)
            if not self.datacenter_obj:
                logging.error(f"Datacenter named {self.config.datacenter} not found")
                raise Exception(f"Datacenter {self.config.datacenter} not found")
        else:
            # Default to the first available datacenter
            self.datacenter_obj = next((dc for dc in self.content.rootFolder.childEntity
                                        if isinstance(dc, vim.Datacenter)), None)
        if not self.datacenter_obj:
            raise Exception("No datacenter object found")

        # Retrieve resource pool (if a cluster is configured, use the cluster's resource pool; otherwise, use the host resource pool)
        compute_resource = None
        if self.config.cluster:
            # Find specified cluster
            for folder in self.datacenter_obj.hostFolder.childEntity:
                if isinstance(folder, vim.ClusterComputeResource) and folder.name == self.config.cluster:
                    compute_resource = folder
                    break
            if not compute_resource:
                logging.error(f"Cluster named {self.config.cluster} not found")
                raise Exception(f"Cluster {self.config.cluster} not found")
        else:
            # Default to the first ComputeResource (cluster or standalone host)
            compute_resource = next((cr for cr in self.datacenter_obj.hostFolder.childEntity
                                      if isinstance(cr, vim.ComputeResource)), None)
        if not compute_resource:
            raise Exception("No compute resource (cluster or host) found")
        self.resource_pool = compute_resource.resourcePool
        logging.info(f"Using resource pool: {self.resource_pool.name}")

        # Retrieve datastore object
        if self.config.datastore:
            # Find specified datastore in the datacenter
            self.datastore_obj = next((ds for ds in self.datacenter_obj.datastoreFolder.childEntity
                                       if isinstance(ds, vim.Datastore) and ds.name == self.config.datastore), None)
            if not self.datastore_obj:
                logging.error(f"Datastore named {self.config.datastore} not found")
                raise Exception(f"Datastore {self.config.datastore} not found")
        else:
            # Default to the datastore with the largest available capacity
            datastores = [ds for ds in self.datacenter_obj.datastoreFolder.childEntity if isinstance(ds, vim.Datastore)]
            if not datastores:
                raise Exception("No available datastore found in the datacenter")
            # Select the one with the maximum free space
            self.datastore_obj = max(datastores, key=lambda ds: ds.summary.freeSpace)
        logging.info(f"Using datastore: {self.datastore_obj.name}")

        # Retrieve network object (network or distributed virtual portgroup)
        if self.config.network:
            # Find specified network in the datacenter network list
            networks = self.datacenter_obj.networkFolder.childEntity
            self.network_obj = next((net for net in networks if net.name == self.config.network), None)
            if not self.network_obj:
                logging.error(f"Network {self.config.network} not found")
                raise Exception(f"Network {self.config.network} not found")
            logging.info(f"Using network: {self.network_obj.name}")
        else:
            self.network_obj = None  # If no network is specified, VM creation can choose to not connect to a network

    def list_vms(self) -> list:
        """List all virtual machine names."""
        vm_list = []
        # Create a view to iterate over all virtual machines
        container = self.content.viewManager.CreateContainerView(self.content.rootFolder, [vim.VirtualMachine], True)
        for vm in container.view:
            vm_list.append(vm.name)
        container.Destroy()
        return vm_list

    def find_vm(self, name: str) -> Optional[vim.VirtualMachine]:
        """Find virtual machine object by name."""
        container = self.content.viewManager.CreateContainerView(self.content.rootFolder, [vim.VirtualMachine], True)
        vm_obj = None
        for vm in container.view:
            if vm.name == name:
                vm_obj = vm
                break
        container.Destroy()
        return vm_obj

    def get_vm_performance(self, vm_name: str) -> Dict[str, Any]:
        """Retrieve performance data (CPU, memory, storage, and network) for the specified virtual machine."""
        vm = self.find_vm(vm_name)
        if not vm:
            raise Exception(f"VM {vm_name} not found")
        # CPU and memory usage (obtained from quickStats)
        stats = {}
        qs = vm.summary.quickStats
        stats["cpu_usage"] = qs.overallCpuUsage  # MHz
        stats["memory_usage"] = qs.guestMemoryUsage  # MB
        # Storage usage (committed storage, in GB)
        committed = vm.summary.storage.committed if vm.summary.storage else 0
        stats["storage_usage"] = round(committed / (1024**3), 2)  # Convert to GB
        # Network usage (obtained from host or VM NIC statistics, latest sample)
        # Here we simply obtain the latest performance counter for VM network I/O
        net_bytes_transmitted = 0
        net_bytes_received = 0
        try:
            pm = self.content.perfManager
            # Define performance counter IDs to query: network transmitted and received bytes
            counter_ids = []
            for c in pm.perfCounter:
                counter_full_name = f"{c.groupInfo.key}.{c.nameInfo.key}.{c.rollupType}"
                if counter_full_name in ("net.transmitted.average", "net.received.average"):
                    counter_ids.append(c.key)
            if counter_ids:
                query = vim.PerformanceManager.QuerySpec(maxSample=1, entity=vm, metricId=[vim.PerformanceManager.MetricId(counterId=cid, instance="*") for cid in counter_ids])
                stats_res = pm.QueryStats(querySpec=[query])
                for series in stats_res[0].value:
                    # Sum data from each network interface
                    if series.id.counterId == counter_ids[0]:
                        net_bytes_transmitted = sum(series.value)
                    elif series.id.counterId == counter_ids[1]:
                        net_bytes_received = sum(series.value)
            stats["network_transmit_KBps"] = net_bytes_transmitted
            stats["network_receive_KBps"] = net_bytes_received
        except Exception as e:
            # If obtaining performance counters fails, log the error but do not terminate
            logging.warning(f"Failed to retrieve network performance data: {e}")
            stats["network_transmit_KBps"] = None
            stats["network_receive_KBps"] = None
        return stats

    def create_vm(self, name: str, cpus: int, memory_mb: int, datastore: Optional[str] = None, network: Optional[str] = None) -> str:
        """Create a new virtual machine (from scratch, with an empty disk and optional network)."""
        # If a specific datastore or network is provided, update the corresponding object accordingly
        datastore_obj = self.datastore_obj
        network_obj = self.network_obj
        if datastore:
            datastore_obj = next((ds for ds in self.datacenter_obj.datastoreFolder.childEntity
                                   if isinstance(ds, vim.Datastore) and ds.name == datastore), None)
            if not datastore_obj:
                raise Exception(f"Specified datastore {datastore} not found")
        if network:
            networks = self.datacenter_obj.networkFolder.childEntity
            network_obj = next((net for net in networks if net.name == network), None)
            if not network_obj:
                raise Exception(f"Specified network {network} not found")

        # Build VM configuration specification
        vm_spec = vim.vm.ConfigSpec(name=name, memoryMB=memory_mb, numCPUs=cpus, guestId="otherGuest")  # guestId can be adjusted as needed
        device_specs = []

        # Add SCSI controller
        controller_spec = vim.vm.device.VirtualDeviceSpec()
        controller_spec.operation = vim.vm.device.VirtualDeviceSpec.Operation.add
        controller_spec.device = vim.vm.device.ParaVirtualSCSIController()  # Using ParaVirtual SCSI controller
        controller_spec.device.deviceInfo = vim.Description(label="SCSI Controller", summary="ParaVirtual SCSI Controller")
        controller_spec.device.busNumber = 0
        controller_spec.device.sharedBus = vim.vm.device.VirtualSCSIController.Sharing.noSharing
        # Set a temporary negative key for the controller for later reference
        controller_spec.device.key = -101
        device_specs.append(controller_spec)

        # Add virtual disk
        disk_spec = vim.vm.device.VirtualDeviceSpec()
        disk_spec.operation = vim.vm.device.VirtualDeviceSpec.Operation.add
        disk_spec.fileOperation = vim.vm.device.VirtualDeviceSpec.FileOperation.create
        disk_spec.device = vim.vm.device.VirtualDisk()
        disk_spec.device.capacityInKB = 1024 * 1024 * 10  # Create a 10GB disk
        disk_spec.device.deviceInfo = vim.Description(label="Hard Disk 1", summary="10 GB disk")
        disk_spec.device.backing = vim.vm.device.VirtualDisk.FlatVer2BackingInfo()
        disk_spec.device.backing.diskMode = "persistent"
        disk_spec.device.backing.thinProvisioned = True  # Thin provisioning
        disk_spec.device.backing.datastore = datastore_obj
        # Attach the disk to the previously created controller
        disk_spec.device.controllerKey = controller_spec.device.key
        disk_spec.device.unitNumber = 0
        device_specs.append(disk_spec)

        # If a network is provided, add a virtual network adapter
        if network_obj:
            nic_spec = vim.vm.device.VirtualDeviceSpec()
            nic_spec.operation = vim.vm.device.VirtualDeviceSpec.Operation.add
            nic_spec.device = vim.vm.device.VirtualVmxnet3()  # Using VMXNET3 network adapter
            nic_spec.device.deviceInfo = vim.Description(label="Network Adapter 1", summary=network_obj.name)
            if isinstance(network_obj, vim.Network):
                nic_spec.device.backing = vim.vm.device.VirtualEthernetCard.NetworkBackingInfo(network=network_obj, deviceName=network_obj.name)
            elif isinstance(network_obj, vim.dvs.DistributedVirtualPortgroup):
                # Distributed virtual switch portgroup
                dvs_uuid = network_obj.config.distributedVirtualSwitch.uuid
                port_key = network_obj.key
                nic_spec.device.backing = vim.vm.device.VirtualEthernetCard.DistributedVirtualPortBackingInfo(
                    port=vim.dvs.PortConnection(portgroupKey=port_key, switchUuid=dvs_uuid)
                )
            nic_spec.device.connectable = vim.vm.device.VirtualDevice.ConnectInfo(startConnected=True, allowGuestControl=True)
            device_specs.append(nic_spec)

        vm_spec.deviceChange = device_specs

        # Get the folder in which to place the VM (default is the datacenter's vmFolder)
        vm_folder = self.datacenter_obj.vmFolder
        # Create the VM in the specified resource pool
        try:
            task = vm_folder.CreateVM_Task(config=vm_spec, pool=self.resource_pool)
            # Wait for the task to complete
            while task.info.state not in [vim.TaskInfo.State.success, vim.TaskInfo.State.error]:
                continue
            if task.info.state == vim.TaskInfo.State.error:
                raise task.info.error
        except Exception as e:
            logging.error(f"Failed to create virtual machine: {e}")
            raise
        logging.info(f"Virtual machine created: {name}")
        return f"VM '{name}' created."

    def clone_vm(self, template_name: str, new_name: str) -> str:
        """Clone a new virtual machine from an existing template or VM."""
        template_vm = self.find_vm(template_name)
        if not template_vm:
            raise Exception(f"Template virtual machine {template_name} not found")
        vm_folder = template_vm.parent  # Place the new VM in the same folder as the template
        if not isinstance(vm_folder, vim.Folder):
            vm_folder = self.datacenter_obj.vmFolder
        # Use the resource pool of the host/cluster where the template is located
        resource_pool = template_vm.resourcePool or self.resource_pool
        relocate_spec = vim.vm.RelocateSpec(pool=resource_pool, datastore=self.datastore_obj)
        clone_spec = vim.vm.CloneSpec(powerOn=False, template=False, location=relocate_spec)
        try:
            task = template_vm.Clone(folder=vm_folder, name=new_name, spec=clone_spec)
            while task.info.state not in [vim.TaskInfo.State.success, vim.TaskInfo.State.error]:
                continue
            if task.info.state == vim.TaskInfo.State.error:
                raise task.info.error
        except Exception as e:
            logging.error(f"Failed to clone virtual machine: {e}")
            raise
        logging.info(f"Cloned virtual machine {template_name} to new VM: {new_name}")
        return f"VM '{new_name}' cloned from '{template_name}'."

    def delete_vm(self, name: str) -> str:
        """Delete the specified virtual machine."""
        vm = self.find_vm(name)
        if not vm:
            raise Exception(f"Virtual machine {name} not found")
        try:
            task = vm.Destroy_Task()
            while task.info.state not in [vim.TaskInfo.State.success, vim.TaskInfo.State.error]:
                continue
            if task.info.state == vim.TaskInfo.State.error:
                raise task.info.error
        except Exception as e:
            logging.error(f"Failed to delete virtual machine: {e}")
            raise
        logging.info(f"Virtual machine deleted: {name}")
        return f"VM '{name}' deleted."

    def power_on_vm(self, name: str) -> str:
        """Power on the specified virtual machine."""
        vm = self.find_vm(name)
        if not vm:
            raise Exception(f"Virtual machine {name} not found")
        if vm.runtime.powerState == vim.VirtualMachine.PowerState.poweredOn:
            return f"VM '{name}' is already powered on."
        task = vm.PowerOnVM_Task()
        while task.info.state not in [vim.TaskInfo.State.success, vim.TaskInfo.State.error]:
            continue
        if task.info.state == vim.TaskInfo.State.error:
            raise task.info.error
        logging.info(f"Virtual machine powered on: {name}")
        return f"VM '{name}' powered on."

    def power_off_vm(self, name: str) -> str:
        """Power off the specified virtual machine."""
        vm = self.find_vm(name)
        if not vm:
            raise Exception(f"Virtual machine {name} not found")
        if vm.runtime.powerState == vim.VirtualMachine.PowerState.poweredOff:
            return f"VM '{name}' is already powered off."
        task = vm.PowerOffVM_Task()
        while task.info.state not in [vim.TaskInfo.State.success, vim.TaskInfo.State.error]:
            continue
        if task.info.state == vim.TaskInfo.State.error:
            raise task.info.error
        logging.info(f"Virtual machine powered off: {name}")
        return f"VM '{name}' powered off."

# Initialize FastMCP server
mcp = FastMCP("VMware ESXI MCP Server", log_level="ERROR",
              dependencies=[],
              debug=True,
              host='0.0.0.0',
              port=5050)



@mcp.tool()
def tool_create_vm(name: str, cpu: int, memory: int, datastore: str = None, network: str = None) -> str:
    """Create a new virtual machine."""

    return manager.create_vm(name, cpu, memory, datastore, network)

@mcp.tool()
def tool_clone_vm(template_name: str, new_name: str) -> str:
    """Clone a virtual machine from a template."""

    return manager.clone_vm(template_name, new_name)

@mcp.tool()
def tool_delete_vm(name: str) -> str:
    """Delete the specified virtual machine."""

    return manager.delete_vm(name)

@mcp.tool()
def tool_power_on(name: str) -> str:
    """Power on the specified virtual machine."""

    return manager.power_on_vm(name)

@mcp.tool()
def tool_power_off(name: str) -> str:
    """Power off the specified virtual machine."""

    return manager.power_off_vm(name)

@mcp.tool()
def tool_list_vms() -> list:
    """Return a list of all virtual machine names."""

    return manager.list_vms()

@mcp.tool()
def resource_vm_performance(vm_name: str) -> dict:
    """Retrieve CPU, memory, storage, and network usage for the specified virtual machine."""

    return manager.get_vm_performance(vm_name)






'''
Below is configuration loading and VMwareManager initialization code
'''

# Parse command-line arguments and environment variables, and load configuration
parser = argparse.ArgumentParser(description="MCP VMware ESXi Management Server")
parser.add_argument("--config", "-c", help="Configuration file path (JSON or YAML)", default=None)
args = parser.parse_args()

# Attempt to load configuration from a file or environment variables
config_data = {}
config_path = args.config or os.environ.get("MCP_CONFIG_FILE")
if config_path:
    # Parse JSON or YAML based on the file extension
    if config_path.endswith((".yml", ".yaml")):
        import yaml
        with open(config_path, 'r') as f:
            config_data = yaml.safe_load(f)
    elif config_path.endswith(".json"):
        with open(config_path, 'r') as f:
            config_data = json.load(f)
    else:
        raise ValueError("Unsupported configuration file format. Please use JSON or YAML")
# Override configuration from environment variables (higher priority than file)
env_map = {
    "VCENTER_HOST": "vcenter_host",
    "VCENTER_USER": "vcenter_user",
    "VCENTER_PASSWORD": "vcenter_password",
    "VCENTER_DATACENTER": "datacenter",
    "VCENTER_CLUSTER": "cluster",
    "VCENTER_DATASTORE": "datastore",
    "VCENTER_NETWORK": "network",
    "VCENTER_INSECURE": "insecure",
    "MCP_API_KEY": "api_key",
    "MCP_LOG_FILE": "log_file",
    "MCP_LOG_LEVEL": "log_level"
}
for env_key, cfg_key in env_map.items():
    if env_key in os.environ:
        val = os.environ[env_key]
        # Boolean type conversion
        if cfg_key == "insecure":
            config_data[cfg_key] = val.lower() in ("1", "true", "yes")
        else:
            config_data[cfg_key] = val

# Construct Config object from config_data
required_keys = ["vcenter_host", "vcenter_user", "vcenter_password"]
for k in required_keys:
    if k not in config_data or not config_data[k]:
        raise Exception(f"Missing required configuration item: {k}")
config = Config(**config_data)

# Initialize logging
log_level = getattr(logging, config.log_level.upper(), logging.INFO)
logging.basicConfig(level=log_level,
                    format="%(asctime)s [%(levelname)s] %(message)s",
                    filename=config.log_file if config.log_file else None)
if not config.log_file:
    # If no log file is specified, output logs to the console
    logging.getLogger().addHandler(logging.StreamHandler())

logging.info("Starting VMware ESXi Management MCP Server...")
# Create VMware Manager instance and connect
manager = VMwareManager(config)

# If an API key is configured, prompt that authentication is required before invoking sensitive operations
if config.api_key:
    logging.info("API key authentication is enabled. Clients must call the authenticate tool to verify the key before invoking sensitive operations")




'''
Below using SSE transport with FastAPI and Starlette
'''


transport = SseServerTransport("/messages/")

async def handle_sse(request):
    scope = request.scope
    # Verify API key: Retrieve from request headers 'Authorization' or 'X-API-Key'
    headers_dict = {k.lower().decode(): v.decode() for (k, v) in scope.get("headers", [])}
    provided_key = None

    if headers_dict.get("authorization"):
        provided_key = headers_dict.get("authorization")
    elif headers_dict.get("x-api-key"):
        provided_key = headers_dict.get("x-api-key")
    if config.api_key and provided_key != f"Bearer {config.api_key}" and provided_key != config.api_key:
        logging.info("No valid API key provided, rejecting SSE connection, provided key is %s", provided_key)
        raise HTTPException(status_code=403, detail="Invalid API Key")

    logging.info("Client connected to SSE endpoint")

    # Prepare bidirectional streams over SSE
    async with transport.connect_sse(
        request.scope,
        request.receive,
        request._send
    ) as (in_stream, out_stream):
        # Run the MCP server: read JSON-RPC from in_stream, write replies to out_stream
        await mcp._mcp_server.run(
            in_stream,
            out_stream,
            mcp._mcp_server.create_initialization_options()
        )


#Build a small Starlette app for the two MCP endpoints
sse_app = Starlette(
    routes=[
        Route("/sse", handle_sse, methods=["GET"]),
        # Note the trailing slash to avoid 307 redirects
        Mount("/messages/", app=transport.handle_post_message)
    ]
)

app = FastAPI()
app.mount("/", sse_app)

if __name__ == "__main__":
    #mcp.run(transport="sse")
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=5050)    