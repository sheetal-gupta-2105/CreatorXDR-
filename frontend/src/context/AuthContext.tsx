
import {
    createContext,
    useCallback,
    useContext,
    useEffect,
    useMemo,
    useState,
  } from 'react'
  import type { ReactNode } from 'react'
  
  import {
    getCurrentUser,
    hasStoredSession,
    loginUser,
    logoutUser,
    registerUser,
    verifyEmail,
  } from '../services/api'
  
  import type { User } from '../services/api'
  
  type AuthContextValue = {
    user: User | null
    loading: boolean
    login: (email: string, password: string) => Promise<void>
    register: (email: string, password: string) => Promise<string>
    verify: (email: string, code: string) => Promise<string>
    logout: () => void
  }
  
  const AuthContext = createContext<AuthContextValue | undefined>(undefined)
  
  export function AuthProvider({ children }: { children: ReactNode }) {
    const [user, setUser] = useState<User | null>(null)
    const [loading, setLoading] = useState(true)
  
    useEffect(() => {
      let active = true
  
      async function restoreSession() {
        if (!hasStoredSession()) {
          if (active) setLoading(false)
          return
        }
  
        try {
          const currentUser = await getCurrentUser()
  
          if (active) {
            setUser(currentUser)
          }
        } catch {
          logoutUser()
  
          if (active) {
            setUser(null)
          }
        } finally {
          if (active) {
            setLoading(false)
          }
        }
      }
  
      void restoreSession()
  
      return () => {
        active = false
      }
    }, [])
  
    const login = useCallback(async (email: string, password: string) => {
      const authenticatedUser = await loginUser(email, password)
      setUser(authenticatedUser)
    }, [])
  
    const register = useCallback(
      async (email: string, password: string) => {
        const result = await registerUser(email, password)
        return result.message
      },
      [],
    )
  
    const verify = useCallback(async (email: string, code: string) => {
      const result = await verifyEmail(email, code)
      return result.message
    }, [])
  
    const logout = useCallback(() => {
      logoutUser()
      setUser(null)
    }, [])
  
    const value = useMemo(
      () => ({
        user,
        loading,
        login,
        register,
        verify,
        logout,
      }),
      [user, loading, login, register, verify, logout],
    )
  
    return <AuthContext.Provider value={value}>{children}</AuthContext.Provider>
  }
  
  export function useAuth() {
    const context = useContext(AuthContext)
  
    if (!context) {
      throw new Error('useAuth must be used inside an AuthProvider.')
    }
  
    return context
  }
  