import React, { useState, useEffect } from "react";
import adminApi from "../api/adminApi";
import { toast } from "react-toastify";
import {
    User,
    Mail,
    Phone,
    Home,
    CheckCircle,
    XCircle,
    X,
    Eye,
    Trash2,
    Building2,
    Loader2,
    RefreshCw,
} from "lucide-react";

// --- Configuration ---
const API_URL = import.meta.env.VITE_API_BASE_URL;

// Helper function (if needed, place here)
// const formatDate = (dateString) => { ... };

// ✅ FIX: DEFINE StatusTag HERE, BEFORE the main component.
const StatusTag = ({ status }) => {
    // Map backend boolean/status to frontend tag style
    const isApproved = status === true || status === "approved";
    const isPending = status === "pending";

    const styles = isApproved
        ? "bg-green-100 text-green-700"
        : isPending
            ? "bg-yellow-100 text-yellow-700"
            : "bg-red-100 text-red-700"; // Assuming false/rejected means rejected

    const label = isApproved
        ? "Approved"
        : isPending
            ? "Pending"
            : "Rejected";

    return (
        <span className={`px-3 py-1 rounded-full text-xs font-semibold ${styles}`}>
            {label}
        </span>
    );
};


const BuilderProjects = () => {
    const [ownersData, setOwnersData] = useState([]);
    const [loading, setLoading] = useState(true);

    // Rejection Modal State
    const [isRejectModalOpen, setIsRejectModalOpen] = useState(false);
    const [rejectingProject, setRejectingProject] = useState(null); // { ownerId, projectId }
    const [rejectionReason, setRejectionReason] = useState("");
    // Auth handled by adminApi via cookies

    /* -----------------------------------------------
      🔥 FETCH OWNERS WITH PROJECTS (Admin Endpoint)
    ------------------------------------------------- */
    const fetchOwnersWithProjects = async () => {
        try {
            setLoading(true);
            // Using adminApi - cookies sent automatically
            const { data } = await adminApi.get(`/api/users/owners-projects`);

            // Map data to the structure expected by the UI component
            const mappedData = data.data.map(owner => ({
                ...owner,
                id: owner._id, // Ensure owner ID is mapped
                projects: owner.projects.map(p => ({
                    ...p,
                    id: p._id, // Use p._id to guarantee the project ID is correct
                    title: p.title,
                    location: p.address?.city || 'N/A',
                    price: `₹${(p.price || 0).toLocaleString('en-IN')}`,
                    // Ensure status mapping reflects the action buttons
                    status: p.isApproved === false ? 'rejected' : p.isApproved === true ? 'approved' : 'pending'
                }))
            }));

            setOwnersData(mappedData);
            setLoading(false);
            toast.success(`Successfully loaded ${mappedData.length} owners.`);

        } catch (error) {
            console.error("API Error:", error);
            setLoading(false);
            toast.error("Failed to fetch data: " + (error.response?.data?.message || "Server Error"));
        }
    };

    /* -----------------------------------------------
      🔥 PROPERTY ACTION HANDLERS
    ------------------------------------------------- */

    // Open rejection modal
    const openRejectModal = (ownerId, projectId) => {
        setRejectingProject({ ownerId, projectId });
        setRejectionReason("");
        setIsRejectModalOpen(true);
    };

    // Submit rejection with reason
    const submitRejection = async () => {
        if (!rejectionReason.trim()) {
            return toast.error("Rejection reason is required");
        }

        const { ownerId, projectId } = rejectingProject;

        try {
            await adminApi.put(`/api/properties/disapprove/${projectId}`, {
                rejectionReason: rejectionReason.trim()
            });

            toast.success("Project rejected successfully!");
            setIsRejectModalOpen(false);
            setRejectingProject(null);

            // Update local state
            setOwnersData(prevOwners => prevOwners.map(owner => {
                if (owner.id === ownerId) {
                    return {
                        ...owner,
                        projects: owner.projects.map(p => {
                            if (p.id === projectId) {
                                return {
                                    ...p,
                                    status: 'rejected',
                                    isApproved: false,
                                };
                            }
                            return p;
                        })
                    };
                }
                return owner;
            }));
        } catch (err) {
            toast.error(err.response?.data?.message || "Failed to reject project.");
        }
    };

    const handleProjectAction = async (ownerId, projectId, action) => {
        if (!projectId) {
            console.error("Missing Project ID for action:", action);
            return toast.error("Error: Cannot perform action, Project ID is missing.");
        }

        // For reject action, open modal instead of direct API call
        if (action === 'reject') {
            openRejectModal(ownerId, projectId);
            return;
        }

        const endpoint =
            action === 'approve'
                ? `/api/properties/approve/${projectId}`
                : `/api/properties/delete/${projectId}`;

        // Confirm dialog for deletion only
        if (action === 'delete') {
            if (!window.confirm("Are you sure you want to permanently delete this project?")) {
                return;
            }
        }

        try {
            let response;
            if (action === 'delete') {
                response = await adminApi.delete(endpoint);
            } else {
                response = await adminApi.put(endpoint, {});
            }

            toast.success(`Project ${action}d successfully!`);

            // Update the local state for instant UI change
            setOwnersData(prevOwners => prevOwners.map(owner => {
                if (owner.id === ownerId) {
                    return {
                        ...owner,
                        projects: owner.projects.filter(p => action !== 'delete' || p.id !== projectId).map(p => {
                            if (p.id === projectId) {
                                return {
                                    ...p,
                                    status: action === 'approve' ? 'approved' : 'rejected',
                                    isApproved: action === 'approve' ? true : false,
                                };
                            }
                            return p;
                        })
                    };
                }
                return owner;
            }));
        } catch (err) {
            toast.error(err.response?.data?.message || `Failed to ${action} project.`);
        }
    };

    useEffect(() => {
        fetchOwnersWithProjects();
    }, []);


    if (loading) {
        return (
            <div className="p-8 min-h-screen flex justify-center items-center bg-gray-100">
                <Loader2 className="w-8 h-8 animate-spin text-purple-600" />
                <span className="ml-4 text-xl font-medium text-gray-700">Loading Owners and Projects...</span>
            </div>
        );
    }

    return (
        <div className="p-2 sm:p-4  min-h-screen space-y-10">

            {/* PAGE TITLE & REFRESH */}
            <div className="flex flex-col sm:flex-row justify-between items-start sm:items-center pb-4 border-b border-gray-300 gap-4">
                <h1 className="text-xl sm:text-3xl font-bold text-gray-800 tracking-tight flex items-center gap-2">
                    🏗️ Builder Project Management
                </h1>
                <button
                    onClick={fetchOwnersWithProjects}
                    className="w-full sm:w-auto px-4 py-2 bg-indigo-600 text-white rounded-lg shadow-md hover:bg-indigo-700 transition-colors font-medium flex items-center justify-center gap-1 text-sm whitespace-nowrap"
                >
                    <RefreshCw className="w-4 h-4" /> Reload All
                </button>
            </div>

            {ownersData.length === 0 && (
                <div className="text-center p-12 bg-white rounded-xl shadow-lg">
                    <h3 className="text-xl font-semibold text-gray-500">No Owners with Projects Found.</h3>
                    <p className="text-gray-400">Ensure owners have the correct 'owner' role and have added properties.</p>
                </div>
            )}

            {ownersData.map((owner) => (
                <div
                    key={owner.id}
                    className="bg-white shadow-xl rounded-xl p-6 space-y-6 border-t-4 border-purple-500"
                >
                    {/* OWNER DETAILS CARD */}
                    <div className="flex flex-col md:flex-row justify-between items-start md:items-center border-b pb-4 mb-4">
                        <div className="flex items-center gap-4">
                            <div className="w-12 h-12 rounded-full bg-gradient-to-br from-pink-300 to-fuchsia-300 flex items-center justify-center shadow-md">
                                <User className="w-6 h-6 text-gray-800" />
                            </div>
                            <div>
                                <h2 className="text-2xl font-extrabold text-purple-700">
                                    {owner.name}
                                </h2>
                                <p className="text-gray-600 flex items-center gap-2 font-medium text-sm">
                                    <Building2 className="w-4" /> {owner.company || 'Independent Owner'}
                                </p>
                            </div>
                        </div>

                        <div className="flex flex-col gap-1 text-gray-700 text-sm mt-3 md:mt-0">
                            <p className="flex items-center gap-2">
                                <Mail className="w-4 text-pink-500" /> {owner.email}
                            </p>
                            <p className="flex items-center gap-2">
                                <Phone className="w-4 text-pink-500" /> {owner.phone || 'N/A'}
                            </p>
                        </div>
                        {/* Project Count for quick reference (optional) */}
                        <span className="text-lg font-bold text-gray-600 mt-2 md:mt-0">
                            Total Projects: {owner.projects.length}
                        </span>
                    </div>

                    {/* PROJECT LIST */}
                    {owner.projects.length > 0 ? (
                        <>
                            <h3 className="text-lg font-bold text-gray-800">
                                📌 {owner.projects.length} Projects under Review
                            </h3>

                            <div className="grid grid-cols-1 md:grid-cols-2 xl:grid-cols-3 gap-6">
                                {owner.projects.map((p) => (
                                    <div
                                        key={p.id}
                                        className="bg-gray-50 shadow-lg hover:shadow-xl transition rounded-xl overflow-hidden border border-gray-200"
                                    >
                                        <img
                                            src={p.images?.[0] || 'https://images.unsplash.com/photo-1516132431682-12f5a65a3962?auto=format&fit=crop&w=800&q=60'}
                                            className="w-full h-40 object-cover"
                                            alt="project image"
                                        />

                                        <div className="p-4 space-y-2">
                                            <h4 className="text-lg font-bold text-purple-700">
                                                {p.title}
                                            </h4>

                                            <p className="text-gray-600 flex items-center gap-2 text-sm">
                                                <Home className="w-4 text-fuchsia-500" /> {p.location}
                                            </p>

                                            <p className="text-gray-800 font-extrabold text-base">{p.price}</p>

                                            <StatusTag status={p.status} />

                                            {/* ACTION BUTTONS */}
                                            <div className="flex  gap-2 pt-3">
                                                {p.status !== "approved" && (
                                                    <button
                                                        onClick={() => handleProjectAction(owner.id, p.id, 'approve')}
                                                        className="flex items-center justify-center w-full px-2 py-2 bg-green-600 text-white rounded-lg text-sm hover:bg-green-700 shadow-md"
                                                    >
                                                        <CheckCircle className="w-4 mr-1" /> Approve
                                                    </button>
                                                )}

                                                {p.status !== "rejected" && (
                                                    <button
                                                        onClick={() => handleProjectAction(owner.id, p.id, 'reject')}
                                                        className="flex items-center justify-center w-full px-2 py-2 bg-red-600 text-white rounded-lg text-sm hover:bg-red-700 shadow-md"
                                                    >
                                                        <XCircle className="w-4 mr-1" /> Reject
                                                    </button>
                                                )}
                                            </div>

                                            <button
                                                onClick={() => handleProjectAction(owner.id, p.id, 'delete')}
                                                className="flex items-center justify-center w-full mt-3 px-3 py-2 bg-gray-200 text-red-600 rounded-lg text-sm hover:bg-red-100 font-semibold"
                                            >
                                                <Trash2 className="w-4 mr-1" /> Delete Project
                                            </button>
                                        </div>
                                    </div>
                                ))}
                            </div>
                        </>
                    ) : (
                        <div className="text-center p-6 text-gray-500 italic bg-gray-50 rounded-xl border border-dashed border-gray-300">
                            This owner currently has no properties listed.
                        </div>
                    )}

                </div>
            ))}

            {/* Rejection Reason Modal */}
            {isRejectModalOpen && (
                <div className="fixed inset-0 z-50 flex items-center justify-center bg-black bg-opacity-50 p-4">
                    <div className="bg-white rounded-2xl shadow-xl w-full max-w-md overflow-hidden">
                        <div className="bg-red-50 px-6 py-4 flex justify-between items-center border-b border-red-100">
                            <h3 className="text-lg font-bold text-red-800">Reject Project</h3>
                            <button onClick={() => setIsRejectModalOpen(false)}>
                                <X className="w-6 h-6 text-gray-500 hover:text-gray-700" />
                            </button>
                        </div>
                        <div className="p-6">
                            <label className="block text-sm font-medium text-gray-700 mb-2">
                                Rejection Reason <span className="text-red-500">*</span>
                            </label>
                            <textarea
                                className="w-full border border-gray-300 rounded-lg p-3 h-32 focus:ring-2 focus:ring-red-500 focus:border-red-500 outline-none"
                                placeholder="Provide a reason for rejection..."
                                value={rejectionReason}
                                onChange={(e) => setRejectionReason(e.target.value)}
                                maxLength={500}
                            />
                            <p className="text-xs text-gray-400 mt-1">{rejectionReason.length}/500 characters</p>
                        </div>
                        <div className="bg-gray-50 px-6 py-4 flex justify-end gap-3">
                            <button
                                onClick={() => setIsRejectModalOpen(false)}
                                className="px-4 py-2 bg-white border border-gray-300 rounded-lg text-sm hover:bg-gray-50"
                            >
                                Cancel
                            </button>
                            <button
                                onClick={submitRejection}
                                className="px-4 py-2 bg-red-600 text-white rounded-lg text-sm font-bold hover:bg-red-700"
                            >
                                Confirm Rejection
                            </button>
                        </div>
                    </div>
                </div>
            )}
        </div>
    );
};

export default BuilderProjects;