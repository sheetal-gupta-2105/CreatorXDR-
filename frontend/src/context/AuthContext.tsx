
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
  updateUserProfile,
  verifyEmail,
} from '../services/api'

import type { User } from '../services/api'

type AuthContextValue = {
  user: User | null
  loading: boolean

  login: (email: string, password: string) => Promise<void>

  register: (
    fullName: string,
    email: string,
    password: string,
  ) => Promise<string>

  updateProfile: (fullName: string) => Promise<void>

  verify: (email: string, code: string) => Promise<string>

  logout: () => void
}

const AuthContext = createContext<AuthContextValue | undefined>(undefined)

export function AuthProvider({ children }: { children: ReactNode }) {
  const [user, setUser] = useState<User | null>(null)
  const [loading, setLoading] = useState(true)

  // Restore the authenticated user when the application loads.
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

  // Login with existing credentials.
  const login = useCallback(async (email: string, password: string) => {
    const authenticatedUser = await loginUser(email, password)
    setUser(authenticatedUser)
  }, [])

  // Register a new user with their full name.
  const register = useCallback(
    async (fullName: string, email: string, password: string) => {
      const result = await registerUser(fullName, email, password)
      return result.message
    },
    [],
  )

  // Update the authenticated user's profile.
  const updateProfile = useCallback(async (fullName: string) => {
    const result = await updateUserProfile(fullName)
    setUser(result.user)
  }, [])

  // Verify the user's email address.
  const verify = useCallback(async (email: string, code: string) => {
    const result = await verifyEmail(email, code)
    return result.message
  }, [])

  // Logout and clear the stored authentication tokens.
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
      updateProfile,
      verify,
      logout,
    }),
    [user, loading, login, register, updateProfile, verify, logout],
  )

  return (
    <AuthContext.Provider value={value}>
      {children}
    </AuthContext.Provider>
  )
}

export function useAuth() {
  const context = useContext(AuthContext)

  if (!context) {
    throw new Error('useAuth must be used inside an AuthProvider.')
  }

  return context
}
