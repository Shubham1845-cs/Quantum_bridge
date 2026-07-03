import { describe, it, expect, vi, beforeEach } from 'vitest';
import { render, screen } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import Input from './Input';

describe('Input Component', () => {
  it('should render with correct properties', () => {
    const { container } = render(
      <Input
        label="Test Label"
        type="text"
        placeholder="Test placeholder"
        value="test"
        onChange={vi.fn()}
      />
    );

    // Check that label is rendered
    expect(screen.getByText(/test label/i)).toBeInTheDocument();
    // Check that input is rendered
    const input = screen.getByPlaceholderText(/test placeholder/i);
    expect(input).toBeInTheDocument();
    expect(input).toHaveValue('test');
  });

  it('should call onChange when input changes', async () => {
    const onChange = vi.fn();
    render(
      <Input
        label="Test Label"
        type="text"
        placeholder="Test placeholder"
        onChange={onChange}
      />
    );

    const input = screen.getByPlaceholderText(/test placeholder/i);
    await userEvent.type(input, 'new value');

    expect(onChange).toHaveBeenCalled();
    expect(onChange).toHaveBeenCalledWith(expect.objectContaining({
      target: expect.objectContaining({
        value: 'new value'
      })
    }));
  });

  it('should show error message when error prop is provided', () => {
    render(
      <Input
        label="Test Label"
        type="text"
        placeholder="Test placeholder"
        error="This is an error"
      />
    );

    // Assuming error is displayed somewhere - adjust based on actual implementation
    expect(screen.getByText(/this is an error/i)).toBeInTheDocument();
  });

  it('should handle different input types', () => {
    const types = ['text', 'email', 'password', 'number'];
    types.forEach(type => {
      const { container } = render(
        <Input
          label="Test Label"
          type={type}
          placeholder="Test placeholder"
        />
      );

      const input = screen.getByPlaceholderText(/test placeholder/i);
      expect(input).toHaveAttribute('type', type);
    });
  });
});