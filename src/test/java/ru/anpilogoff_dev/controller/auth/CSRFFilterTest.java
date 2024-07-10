package ru.anpilogoff_dev.controller.auth;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;
import java.io.IOException;

import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
class CSRFFilterTest {

    @InjectMocks
    private CSRFFilter csrfFilter;

    @Mock
    private HttpServletRequest request;

    @Mock
    private HttpServletResponse response;

    @Mock
    private HttpSession session;

    @Mock
    private FilterChain filterChain;

    @BeforeEach
    public void setUp() {
        when(request.getSession(false)).thenReturn(session);
    }

    @Test
    public void testDoFilter_ValidCSRFToken() throws IOException, ServletException {
        when(request.getMethod()).thenReturn("POST");
        when(request.getParameter("csrfToken")).thenReturn("valid-token");
        when(session.getAttribute("csrfToken")).thenReturn("valid-token");

        csrfFilter.doFilter(request, response, filterChain);

        verify(session, never()).invalidate();
        verify(response, never()).sendRedirect("/auth");
        verify(filterChain).doFilter(request, response);
    }

    @Test
    public void testDoFilter_InvalidCSRFToken() throws IOException, ServletException {
        when(request.getMethod()).thenReturn("POST");
        when(request.getParameter("csrfToken")).thenReturn("invalid-token");
        when(session.getAttribute("csrfToken")).thenReturn("valid-token");

        csrfFilter.doFilter(request, response, filterChain);

        verify(session).invalidate();
        verify(response).sendRedirect("/auth");
        verify(filterChain, never()).doFilter(request, response);
    }

    @Test
    public void testDoFilter_NoCSRFToken() throws IOException, ServletException {
        when(request.getMethod()).thenReturn("POST");
        when(request.getParameter("csrfToken")).thenReturn(null);

        csrfFilter.doFilter(request, response, filterChain);

        verify(session).invalidate();
        verify(response).sendRedirect("/auth");
        verify(filterChain, never()).doFilter(request, response);
    }

    @Test
    public void testDoFilter_GETRequest() throws IOException, ServletException {
        when(request.getMethod()).thenReturn("GET");

        csrfFilter.doFilter(request, response, filterChain);

        verify(filterChain).doFilter(request, response);
    }
}