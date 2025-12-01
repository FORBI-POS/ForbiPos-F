import { useState } from "react";
import { useNavigate } from "react-router-dom";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { toast } from "sonner";
import { useAuthStore } from "@/store/authStore";
import { API_BASE_URL } from "@/utils/apiConfig";

export default function Login() {
    const [username, setUsername] = useState("");
    const [password, setPassword] = useState("");
    const [loading, setLoading] = useState(false);
    const navigate = useNavigate();
    const login = useAuthStore((state) => state.login);

    const handleLogin = async (e: React.FormEvent) => {
        e.preventDefault();
        setLoading(true);

        try {
            const response = await fetch(`${API_BASE_URL}/api/auth/login`, {
                method: "POST",
                headers: {
                    "Content-Type": "application/json",
                },
                body: JSON.stringify({ username, password }),
            });

            const data = await response.json();

            if (response.ok) {
                toast.success("Login Successful", {
                    description: `Welcome back, ${data.username}!`,
                });
                login(data);

                let redirectPath = "/";

                if (data.role === 'admin' || (data.role?.name === 'Admin')) {
                    redirectPath = "/";
                } else if (typeof data.role === 'object' && data.role?.permissions) {
                    const permissions = data.role.permissions;
                    const priorityRoutes = [
                        { key: 'dashboard', path: '/' },
                        { key: 'billing', path: '/billing' },
                        { key: 'invoices', path: '/invoices' },
                        { key: 'customers', path: '/customers' },
                        { key: 'payments', path: '/payments' },
                        { key: 'products', path: '/products' },
                        { key: 'purchases', path: '/purchases' },
                        { key: 'inventory', path: '/inventory' },
                        { key: 'suppliers', path: '/suppliers' },
                        { key: 'reports', path: '/reports' },
                        { key: 'expenses', path: '/expenses' },
                        { key: 'employees', path: '/employees' },
                        { key: 'settings', path: '/settings' },
                    ];

                    const firstAllowed = priorityRoutes.find(route => permissions[route.key]);
                    if (firstAllowed) {
                        redirectPath = firstAllowed.path;
                    }
                }

                navigate(redirectPath);
            } else {
                throw new Error(data.message || "Login failed");
            }
        } catch (error: any) {
            toast.error("Error", {
                description: error.message,
            });
        } finally {
            setLoading(false);
        }
    };

    return (
        <div className="flex items-center justify-center min-h-screen bg-white">
            <div className="absolute top-8 text-center">
                <h1 className="text-3xl font-bold text-blue-800 tracking-wide">FORBI - POS</h1>
                <p className="text-sm text-gray-500 mt-1">Secure Login Portal</p>
            </div>

            <Card className="w-[350px] shadow-lg border border-blue-800/20 rounded-xl">
                <CardHeader className="text-center">
                    <CardTitle className="text-xl font-semibold text-blue-800">Login</CardTitle>
                    <CardDescription className="text-gray-600">
                        Access your dashboard
                    </CardDescription>
                </CardHeader>

                <CardContent>
                    <form onSubmit={handleLogin} className="space-y-5">
                        <div className="space-y-1">
                            <Label htmlFor="username" className="text-blue-800 font-medium">
                                Username
                            </Label>
                            <Input
                                id="username"
                                placeholder="admin"
                                className="border-blue-800/40 focus-visible:ring-blue-800"
                                value={username}
                                onChange={(e) => setUsername(e.target.value)}
                                required
                            />
                        </div>

                        <div className="space-y-1">
                            <Label htmlFor="password" className="text-blue-800 font-medium">
                                Password
                            </Label>
                            <Input
                                id="password"
                                type="password"
                                className="border-blue-800/40 focus-visible:ring-blue-800"
                                value={password}
                                onChange={(e) => setPassword(e.target.value)}
                                required
                            />
                        </div>

                        <Button
                            type="submit"
                            className="w-full bg-blue-800 hover:bg-blue-700 text-white"
                            disabled={loading}
                        >
                            {loading ? "Logging in..." : "Login"}
                        </Button>
                    </form>
                </CardContent>
            </Card>
        </div>
    );
}
